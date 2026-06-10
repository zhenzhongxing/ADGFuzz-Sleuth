#用 ASAN 触发目标漏洞的崩溃 → 捕获精准的崩溃栈追踪 → 解析出漏洞触发的关键代码位置，为后续静态分析提供靶向目标（避免全程序无差别分析）。



#!/bin/bash

VULN=$1 #CVE-2023-0799,第一个命令行参数
VULNFILE=$2 #漏洞信息文件，包含了漏洞的基本信息，如项目路径、可执行文件路径、触发参数等，第二个命令行参数
TOOL='get_trace.py' #解析 ASAN 生成的崩溃日志，提取出漏洞触发的关键代码位置，供后续静态分析使用
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt' #漏洞信息表，包含了多个漏洞的基本信息，每行记录一个漏洞的信息，字段之间用制表符分隔，包括 CVE 编号、项目路径、可执行文件路径、触发参数等


if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then 
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}') #从漏洞信息表中提取出项目路径，并拼接成完整路径，存储在变量 PROJECT 中
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}') #从漏洞信息表中提取出漏洞信息路径，并拼接成完整路径，存储在变量 INFO 中

	if [ -d $INFO'/crash_example' ]; then #检查 $INFO/crash_example 目录是否存在，如果存在则说明之前已经生成过崩溃日志，需要先清理掉旧的日志文件；如果不存在则说明是第一次生成崩溃日志，需要创建该目录。
		echo 'reseting...'
		rm -rf $INFO'/crash_example/'*
	else
		echo 'creating...'
		mkdir $INFO'/crash_example'
	fi

	echo '==============================='

	TARGET=$INFO'/crash_example/asan.txt' #定义了一个变量 TARGET，表示 ASAN 生成的崩溃日志文件的路径，命名为 asan.txt，存储在 $INFO/crash_example 目录下

	EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}') #从漏洞信息表中提取出可执行文件路径，并拼接成完整路径，存储在变量 EXE 中
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}') #从漏洞信息表中提取出触发参数，并存储在变量 FLAG 中，触发参数中可能包含 @@ 符号，表示需要替换成输入文件的路径

	# INPUT=$INFO'/'$(grep $VULN $TABLE | awk -F '\t' '{print $5}')

	# INITFILE=$(grep $VULN $TABLE | awk -F '\t' '{print $6}')

	#if [[ -z $INITFILE ]];then
	#	FILE=$INITFILE
	#else

	#	if [[ $INITFILE == '/tmp/foo' ]] || [[ $INITFILE == '/dev/null' ]]; then
	#		FILE=$INITFILE
	#	else
	#		FILE=$INFO'/'$INITFILE
	#	fi
	#fi

	TRACE_FORMAT='stack_trace_format="[frame=%n, function=%f, location=%S]"' #定义了一个变量 TRACE_FORMAT，表示 ASAN 生成的崩溃日志中栈追踪的格式，包含了函数名、文件名和代码位置等信息，供后续解析使用
	LOG_PATH='log_path='$TARGET #定义了一个变量 LOG_PATH，表示 ASAN 生成的崩溃日志文件的路径，供后续解析使用
	OPT='halt_on_error=0' #定义了一个变量 OPT，表示 ASAN 的选项，halt_on_error=0 表示当 ASAN 检测到错误时不立即终止程序，而是继续执行下去，以便捕获更多的错误信息

	INPUT=$INFO'/poc' #定义了一个变量 INPUT，表示漏洞的 PoC 文件的路径，命名为 poc，存储在 $INFO 目录下

	PARAM="${FLAG/@@/$INPUT}" #定义了一个变量 PARAM，表示触发参数中 @@ 符号被替换成输入文件路径后的字符串，供后续执行使用

	echo $EXE $PARAM 

	ASAN_OPTIONS=$TRACE_FORMAT:$LOG_PATH:$OPT $EXE $PARAM #使用 ASAN 触发目标漏洞的崩溃，生成崩溃日志文件 $TARGET
	echo '==============================='

	if ls $TARGET*; then #检查 $TARGET* 是否存在，如果存在则说明 ASAN 已经生成了崩溃日志文件，可以使用工具进行解析；如果不存在则说明 ASAN 没有生成崩溃日志文件，可能是因为没有触发漏洞或者 ASAN 配置有误，需要检查相关设置。
        	python $TOOL `ls $TARGET*` $VULNFILE
	else
        	echo 'no TARGET!'
	fi
else
	echo 'no this CVE!'
fi

#分析 get_trace.py：看它如何从 ASAN 栈日志中提取关键栈帧（这是靶向分析的核心）；
#查看 VulnTable.txt：确认所有测试漏洞的配置格式；
#查看 asan.txt：实际看崩溃栈的内容，理解漏洞触发的调用链。
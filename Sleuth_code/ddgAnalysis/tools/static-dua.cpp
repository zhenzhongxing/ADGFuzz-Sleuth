//===-- static-dua.cpp - Static def/use analysis ----------------*- C++ -*-===//
///
/// \file
/// Perform a static def-use chain analysis. 
///
//===----------------------------------------------------------------------===//

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/InitializePasses.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/JSON.h>

#include "MemoryModel/PointerAnalysis.h"

#include "fuzzalloc/Analysis/DefUseChain.h"
#include "fuzzalloc/Streams.h"

using namespace llvm;
using namespace SVF;

namespace {
//
// Command-line options
//

	static cl::OptionCategory Cat("Static def-use chain analysis"); //这是一个选项分类，可以在帮助信息中显示
	static cl::opt<std::string> BCFilename(cl::Positional, cl::desc("<BC file>"), //这是一个位置参数，必须提供，描述为"<BC file>"
                                       cl::value_desc("path"), cl::Required,
                                       cl::cat(Cat));
	static cl::opt<std::string> OutJSON("out", cl::desc("Output JSON"), //这是一个选项参数，名称为"out"，描述为"Output JSON"
                                    cl::value_desc("path"), cl::cat(Cat));
} // anonymous namespace

int main(int argc, char *argv[]) { 
	cl::ParseCommandLineOptions(argc, argv, "Static def-use chain analysis"); //解析命令行选项，显示帮助信息

  // Parse bitcode
	status_stream() << "Parsing " << BCFilename << "...\n"; //输出状态信息，显示正在解析的文件
	LLVMContext Ctx; //创建一个LLVM上下文对象，用于管理LLVM IR的内存和类型信息
	SMDiagnostic Err; //创建一个SMDiagnostic对象，用于存储解析错误信息
	auto Mod = parseIRFile(BCFilename, Err, Ctx); //调用parseIRFile函数解析指定的BC文件
	if (!Mod) { //如果解析失败，输出错误信息并退出
    error_stream() << "Failed to parse `" << BCFilename
                   << "`: " << Err.getMessage() << '\n';
    ::exit(1);
  }

  // Get static def-use chains
	auto& Registry = *PassRegistry::getPassRegistry(); //获取LLVM PassRegistry的引用，用于注册和管理分析和转换Pass
	initializeCore(Registry); //初始化LLVM核心分析和转换Pass
	initializeAnalysis(Registry); //初始化LLVM分析Pass

	legacy::PassManager PM; //创建一个LLVM PassManager对象，用于管理和运行Pass
	auto* DUA = new DefUseChain; //创建一个DefUseChain Pass对象，用于执行静态def-use链分析
	PM.add(DUA); //将DefUseChain Pass添加到PassManager中，以便在运行PassManager时执行该分析
	PM.run(*Mod); //运行PassManager，传入解析得到的Module对象，执行DefUseChain分析，分析结果将保存在DUA对象中

	const auto& DefUseChains = DUA->getDefUseChains(); //获取DefUseChain分析的结果，即静态def-use链，存储在DefUseChains中（关键）

  // Save Output JSON
	if (!OutJSON.empty()) { //如果指定了输出JSON文件路径，执行以下代码块
		const auto& NumDefs = DefUseChains.size(); //获取def-use链的数量，存储在NumDefs中
		json::Array J; //创建一个JSON数组对象，用于存储def-use链的序列化结果
		J.reserve(NumDefs); //预先分配JSON数组的容量，以提高性能，避免在添加元素时频繁重新分配内存

		status_stream() << "Serializing def/use chains to JSON...\n"; //输出状态信息，显示正在序列化def-use链为JSON格式
		for (const auto& DUEnum : enumerate(DefUseChains)) { //使用enumerate函数遍历DefUseChains，获取每个def-use链的索引和内容，存储在DUEnum中
			const auto& [Def, Uses] = DUEnum.value(); //解构DUEnum的值，获取def和use列表，存储在Def和Uses中

			J.push_back({ toJSON(Def), toJSON(Uses) }); //将def和use列表转换为JSON格式，并将它们作为一个JSON对象添加到JSON数组J中

			const auto& Idx = DUEnum.index(); //获取当前def-use链的索引，存储在Idx中
			if (Idx % ((NumDefs + (10 - 1)) / 10) == 0) { //每当处理的def-use链数量达到总数量的10%时，输出一次进度信息，显示当前的处理进度
				status_stream() << "  ";
				write_double(outs(), static_cast<float>(Idx) / NumDefs,
							FloatStyle::Percent);
				outs() << " defs serialized\r";
			}
		}

    std::error_code EC;
    raw_fd_ostream OS(OutJSON, EC, sys::fs::OF_Text);
    if (EC) {
      error_stream() << "Unable to open " << OutJSON << '\n';
      ::exit(1);
    }

    status_stream() << "Writing to " << OutJSON << "...\n";
    OS << std::move(J);
    OS.flush();
    OS.close();
  }

  // Cleanup
  llvm_shutdown();

  return 0;
}


//ddgAnalysis/lib/fuzzalloc/Analysis/DefUseChain.cpp
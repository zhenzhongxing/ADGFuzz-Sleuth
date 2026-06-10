# Sleuth

## Getting Started

### Docker Container (Recommended)

To simplify the testing process of the artifacts, we provide a docker container which can be downloaded from an online docker hub. Please note that the size of our docker container the dataset is about 12GB, so please prepare sufficient disk space. You can install and run the docker files by following commands below.

```bash
docker pull xingkongwhl/sleuth:latest   # or download the package to build images: docker import docker_sleuth.tar xingkongwhl/sleuth:latest
docker run -dit --privileged --name sleuth xingkongwhl/sleuth:latest /bin/bash
docker exec -it sleuth /bin/bash
```

### Setup your environment (Not use docker)

If not using docker, please follow these steps to set up your environment (assumes a modern Ubuntu OS, `>= 18.04 && <= 20.04`, LLVM v12, Python 3.8):

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev screen
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
pip install contourpy==1.1.0 cycler==0.11.0 fonttools==4.40.0 importlib-resources==5.12.0 kiwisolver==1.4.4 matplotlib==3.7.1 numpy==1.24.3 packaging==23.1 pandas==2.0.3 Pillow==9.5.0 pip==20.0.2 Pygments==2.3.1 pyparsing==3.1.0 python-dateutil==2.8.2 pytz==2024.1 PyYAML==5.3.1 scipy==1.10.1 setuptools==45.2.0 six==1.16.0 tzdata==2024.1 wheel==0.34.2 wllvm==1.3.1 xlwt==1.3.0 zipp==3.15.0
```

DDGAnalysis is our static analyzer for generating memory relevant graph. It depends on the support of SVF and z3. To build:

1. Build z3
    ```bash
    export SLEUTH_PATH=/path/to/Sleuth_code     # replace to your path
    cd $SLEUTH_PATH/ddgAnalysis
    git clone https://github.com/z3prover/z3
    git -C z3 checkout z3-4.8.8
    mkdir -p z3/build
    cd z3/build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=$(realpath ../install) -DZ3_BUILD_LIBZ3_SHARED=False
    make -j
    make install
    ```
    Don't forget set the `SLEUTH_PATH`, which stores the source code.

2. Build DDGAnalysis
    ```bash
    cd $SLEUTH_PATH/ddgAnalysis
    mkdir build
    cd build
    cmake .. \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DLLVM_DIR=$(llvm-config --cmakedir) \
        -DZ3_DIR=/path/to/z3/install
    make -j
    ```

3. Build Sleuth

    Our primary tool for exploring bug impacts, based on AFLplusplus. To build:
    ```bash
    cd $SLEUTH_PATH/Sleuth
    make source-only NO_SPLICING=1      # Don't forget NO_SPLICING=1
    ```

### Usage Example

We use CVE-2023-0799 as an example. If you want to test a new CVE not in our benchmark, please refer to [script/README.md](src/script/README.md).

1. Preparing the required program and PoC.

    ```bash
    cd $SLEUTH_PATH/src
    mkdir -p project/libtiff_project
    cd project/libtiff_project
    git clone https://gitlab.com/libtiff/libtiff.git libtiff
    mkdir CVE-2023-0799
    wget https://gitlab.com/libtiff/libtiff/uploads/1e3a6eb21fb040b54ad05f9ce97e929a/poc.zip
    unzip poc.zip -d CVE-2023-0799 && rm -rf poc.zip
    ```

2. Build the target program. (For convenience, using the provided script)
    ```bash
    cd $SLEUTH_PATH/src/script/run_model
    ./CVE-2023-0799.sh
    ```
3. Run Sleuth.
    ```bash
    cd $SLEUTH_PATH/src/exec
    python autoRun.py CVE-2023-0799 10m 1 SLEUTH
    ```

4. Analysis crash (only run sleuth, don't mind the error message.)
    ```bash
    cd $SLEUTH_PATH/src/exec/crash_analysis
    ./crash_run.sh CVE-2023-0799
    ```
5. Generate evaluation results of new impacts
    ```bash
    cd ../generate_result
    python impact_deal.py CVE-2023-0799
    python count.py
    ```
6. Generate evaluation results for the severity scores.
    ```bash
    python severity_score.py
    ```
The result is save in `$SLEUTH_PATH/Experiment/result`

## Detailed Description

### Code Structure

We list the program directories and some of their files which can be used by artifact evaluations as follows.

- ./Sleuth : The folder storing the source code of our instrument and bug impacts exploration fuzzing tool. 
- ./ddgAnalysis : The folder storing the source code of our static analyzer. 
- ./src : The folder containing the scripts of evaluation.
    - evn/ : Compiling environment.
    - script/ : The directory to run all the experimental setups.
    - exec/ : The directory of result analysis scripts.
        - crash_analysis/ : The directory of scripts for integrating crash results.
        - generate_result/ : The directory of scripts to generate the corresponding tables/figures in the paper.
        - fix_analysis/ : The directory of scripts for integrating patch testing results.
        - autoRun.py : The scripts for automated fuzzing of each test case.
    - vuln_tool/ : The folder of some analysis components.
    - vulnInfo/ : The folder where the preset and processed data is saved.
- ./paper : Data to reproduce our paper's results and the experiment data.
    - data_zip : Data logs to reproduce.
    - result : Paper's experiment data.
    - seeds : PoCs with new impacts.
- ./benchmark : Test cases of our benchmark.
- ./Experiment : The folder where the evaluation results are saved.
    - GraphOfTime/ : The folder where the comparison of the time to discover new impacts are saved.
    - Unique_Impact/ : The folder where the differential impacts discovered by Sleuth are saved.
    - Unique_Crash_Compare/ : The folder where the impacts discovered by Sleuth, afl-cexp and Evocatio are saved.
    - New_Impact_Table-2.json : The results corresponding to Table 2 in the paper.
    - Overall_NewBugImpact.png : The results corresponding to Figure 4 in the paper. (You can test only the highlighted CVEs in Table 2 to reproduce the results in the paper). 
    - NewImpact_Overtime.png : The results corresponding to Figure 5(a) in the paper.
    - SameImpact_Overtime.png : The results corresponding to Figure 5(b) in the paper.
    - NewImpact_Efficiency.xls : The results corresponding to Table 3 in the paper.
    - Severity_score_Table-4.json : The results corresponding to Table 4 in the paper.

### How to reproduce the results of our paper

We compare Sleuth with [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) and [Evocatio](https://github.com/HexHive/Evocatio).
Since running all test cases would take several weeks, we have saved the logs from these runs to facilitate quick reproduction of the results in our paper. Our logs are saved in [paper/data_zip](paper/data_zip/)

Quickly Reproduce:
- unzip the organized data
    ```bash
    cd $SLEUTH_PATH/src/exec/generate_result
    rm -rf $SLEUTH_PATH/paper/CVE*
    python $SLEUTH_PATH/paper/data_zip/tar.py
    ```
- reproduce result (take approximately 20 minute)
    ```bash
    python paper_result.py
    ```
The result is save in `$SLEUTH_PATH/Experiment/result`. Each result corresponds to the figures in the paper, please refer to the previous section [Code Structure](#code-structure). Experiment corresponding to Table 5 involved extensive manual analysis, so we are not including it in the automated script.

If you want to manually run all the experimental processes, please refer to [script/README_COMP.md](src/script/README_COMP.md) and [script/README_PATCH.md](src/script/README_PATCH.md).



#!/bin/bash
# ============================================================
# ADGFuzz + Sleuth Integration - Ubuntu Environment Setup
# Run on Ubuntu 20.04 or 22.04
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.."
echo "[+] Working directory: $WORK_DIR"

# ---------- Basic Dependencies ----------
echo "[+] Installing basic dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential python3-dev python3-pip \
    automake cmake git flex bison libglib2.0-dev libpixman-1-dev \
    python3-setuptools cargo libgtk-3-dev screen \
    lld-12 llvm-12 llvm-12-dev clang-12 \
    gcc-$(gcc --version | head -n1 | sed 's/\..*//' | sed 's/.* //')-plugin-dev \
    libstdc++-$(gcc --version | head -n1 | sed 's/\..*//' | sed 's/.* //')-dev \
    openjdk-17-jdk ant software-properties-common \
    gnome-terminal

# ---------- Python Dependencies ----------
echo "[+] Installing Python dependencies..."
pip install pymavlink numpy pandas geopy
pip install contourpy==1.1.0 cycler==0.11.0 fonttools==4.40.0 \
    importlib-resources==5.12.0 kiwisolver==1.4.4 matplotlib==3.7.1 \
    packaging==23.1 Pillow==9.5.0 Pygments==2.3.1 pyparsing==3.1.0 \
    python-dateutil==2.8.2 pytz==2024.1 PyYAML==5.3.1 scipy==1.10.1 \
    setuptools==45.2.0 six==1.16.0 tzdata==2024.1 wheel==0.34.2 \
    wllvm==1.3.1 xlwt==1.3.0 zipp==3.15.0

# ---------- ArduPilot SITL ----------
echo "[+] Setting up ArduPilot SITL..."
ARDUPILOT_HOME="$HOME/work/ArduPilot"
if [ ! -d "$ARDUPILOT_HOME" ]; then
    mkdir -p "$HOME/work"
    cd "$HOME/work"
    git clone https://github.com/ArduPilot/ardupilot.git ArduPilot
    cd ArduPilot
    git checkout 564879594ebb8d31c6400461b96f5dc442f14533
    git submodule update --init --recursive
    Tools/environment_install/install-prereqs-ubuntu.sh -y
    . ~/.profile
    echo "[+] ArduPilot installed at $ARDUPILOT_HOME"
else
    echo "[+] ArduPilot already exists at $ARDUPILOT_HOME"
fi

# ---------- PX4 SITL (Optional) ----------
echo "[+] Setting up PX4 SITL (optional)..."
PX4_HOME="$HOME/work/PX4"
if [ ! -d "$PX4_HOME" ]; then
    cd "$HOME/work"
    git clone https://github.com/PX4/PX4-Autopilot.git PX4
    cd PX4
    git checkout d35c5f4a4e9515542d9527594f339cd97ab0c70b
    git submodule update --init --recursive
    ./Tools/setup/ubuntu.sh -y
    echo "[+] PX4 installed at $PX4_HOME"
else
    echo "[+] PX4 already exists at $PX4_HOME"
fi

# ---------- Sleuth DDGAnalysis ----------
echo "[+] Building Sleuth DDGAnalysis..."
SLEUTH_PATH="$WORK_DIR/Sleuth_code"
export SLEUTH_PATH

# Build z3
if [ ! -d "$SLEUTH_PATH/ddgAnalysis/z3/build" ]; then
    cd "$SLEUTH_PATH/ddgAnalysis"
    if [ ! -d "z3" ]; then
        git clone https://github.com/z3prover/z3
    fi
    git -C z3 checkout z3-4.8.8
    mkdir -p z3/build
    cd z3/build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=$(realpath ../install) \
        -DZ3_BUILD_LIBZ3_SHARED=False
    make -j2
    make install
    echo "[+] z3 built successfully"
fi

# Build DDGAnalysis
if [ ! -d "$SLEUTH_PATH/ddgAnalysis/build" ]; then
    cd "$SLEUTH_PATH/ddgAnalysis"
    mkdir -p build
    cd build
    cmake .. \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DLLVM_DIR=$(llvm-config --cmakedir) \
        -DZ3_DIR="$SLEUTH_PATH/ddgAnalysis/z3/install"
    make -j2
    echo "[+] DDGAnalysis built successfully"
fi

# ---------- Sleuth (AFLplusplus-based) ----------
echo "[+] Building Sleuth fuzzer..."
cd "$SLEUTH_PATH/Sleuth"
make source-only NO_SPLICING=1
echo "[+] Sleuth fuzzer built successfully"

# ---------- Environment Variables ----------
echo "" >> ~/.bashrc
echo "# ADGFuzz + Sleuth Integration" >> ~/.bashrc
echo "export ARDUPILOT_HOME=$ARDUPILOT_HOME" >> ~/.bashrc
echo "export PX4_HOME=$PX4_HOME" >> ~/.bashrc
echo "export SLEUTH_PATH=$SLEUTH_PATH" >> ~/.bashrc
echo "export ADGFUZZ_HOME=$WORK_DIR/ADGFuzz-main" >> ~/.bashrc

echo ""
echo "============================================"
echo "[+] Setup complete! Environment variables:"
echo "    ARDUPILOT_HOME=$ARDUPILOT_HOME"
echo "    PX4_HOME=$PX4_HOME"
echo "    SLEUTH_PATH=$SLEUTH_PATH"
echo "    ADGFUZZ_HOME=$WORK_DIR/ADGFuzz-main"
echo ""
echo "Please run: source ~/.bashrc"
echo "Then verify:"
echo "  1. cd \$ARDUPILOT_HOME && ./Tools/autotest/sim_vehicle.py -v ArduCopter --console --map -w"
echo "  2. cd \$ADGFUZZ_HOME && python adgfuzz.py --help"
echo "  3. \$SLEUTH_PATH/Sleuth/afl-fuzz --help"
echo "============================================"

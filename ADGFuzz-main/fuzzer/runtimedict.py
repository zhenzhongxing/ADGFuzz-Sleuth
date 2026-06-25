import re
import logging
import pandas as pd
import numpy as np
import random
import math
from decimal import Decimal, getcontext
import ast

class MavcmdDictionary:
    def __init__(self):
        self.cmd_set = {}
        self.empty = 0

        self.load_paramters()


    def load_paramters(self, file_path = 'data/mav_cmds1.csv'):
        # file_path = '../data/mav_cmds1.csv'  # for test
        df = pd.read_csv(file_path)
        for index, row in df.iterrows():
            #CMD_Name,Index,param1,param2,param3,param4,param5,param6,param7
            cmd_name = row['CMD_Name']
            cmd_index = row['Index']
            param1 = row['param1']
            param2 = row['param2']
            param3 = row['param3']
            param4 = row['param4']
            param5 = row['param5']
            param6 = row['param6']
            param7 = row['param7']

            self.cmd_set[cmd_name] = {
                'Index': cmd_index,
                'param1': param1,
                'param2': param2,
                'param3': param3,
                'param4': param4,
                'param5': param5,
                'param6': param6,
                'param7': param7
            }
    def get_cmd_parameter(self, cmd_name):
        return self.cmd_set.get(cmd_name, None)

    def get_index(self, cmd_name):
        param = self.cmd_set.get(cmd_name)
        return param['Index']
    def return_a_value(self, param):
        # Memory-fuzz: 25% chance to return extreme values for any command param
        if random.random() < 0.25:
            return random.choice([-1, 0, 255, 65535, -32768,
                                  random.randint(0, 65535),
                                  -random.randint(1, 32768)])

        if param == 'E':
            return 0
        elif param == 'N':
            return random.randint(0, 1000)
        elif isinstance(param, str) and param.startswith('[') and param.endswith(']'):
            param_list = param[1:-1].split(',')
            min_val = int(param_list[0]) if param_list[0] != 'N' else random.randint(0, 1000)
            if param_list[1] != 'N':
                max_val = int(param_list[1])
                if min_val>max_val:
                    return max_val
            else:
                max_val = random.randint(min_val, min_val + 1000)
            step = int(param_list[2]) if param_list[2] != 'N' else 1
            return random.choice(range(min_val, max_val + 1, step))
        elif param == 'm':
            return random.randint(0, 1000)
        elif param == 'deg':
            return random.choice(range(-180, 360, 45))
        elif param == 'm/s':
            return random.randint(0, 50)
        elif param == 'rad':
            return random.randint(-314, 628)/100.0
        elif param == 's':
            return random.randint(0, 100)
        elif param == 'degE7':
            return random.randint(-1800000000, 1800000000)
        elif param == 'deg/s':
            return random.randint(0, 360)
        else:
            return 1

    def get_mav_param_set(self, cmd_name):
        ''' Returns a concrete parameter instance of MAV_CMD_XXX : param[0-6], aka param1-7 '''
        data = self.get_cmd_parameter(cmd_name)
        #FIXME: If it doesn't exist? Leave it for now

        #result = [self.return_a_value(param) for param in data[1:]]
        result = [self.return_a_value(data[f'param{i}']) for i in range(1, 8)]
        return result





class RuntimeDictionary:
    '''
    Process the parameters.csv file to get the values of the parameters
    max value, min value, return a random value, etc.
    '''
    def __init__(self):
        #self.signature_splitter = '%FUZZER%'
        #self.array_pattern = re.compile('\[[0-9]+\]')

        #Parameter_Name,Increment,Range_Min,Range_Max,Value
        #FORMAT_VERSION,    N,        1,      255,      N
        self.parameters = {}

        # constant
        self.rangemin = 0
        self.rangemax = 10000 # can fix
        self.increment = 1

        # init: auto or called after instantiation
        self.load_parameters()

    def load_parameters(self, csv_file='data/ap-copter-v470.csv'):
        # Relative exec_path to adgfuzz.py(../)

        # read csv file to DataFrame
        df = pd.read_csv(csv_file)

        for index, row in df.iterrows():
            param_name = row['Parameter_Name']
            increment = row['Increment']
            range_min = row['Range_Min']
            range_max = row['Range_Max']
            #range_min = None if row['Range_Min'] == 'N' else row['Range_Min']
            #range_max = None if row['Range_Max'] == 'N' else row['Range_Max']
            value = row['Value']

            self.parameters[param_name] = {
                'Increment': increment,
                'Range_Min': range_min,
                'Range_Max': range_max,
                'Value': value
            }

    def get_parameter(self, param_name):
        return self.parameters.get(param_name, None)

    # def parse_csv(self):
    #     file = '../data/parameters-plane-v460.csv'
    #     try:
    #         data = pd.read_csv(file)
    #         #print(data)
    #         data.fillna('N', inplace=True)
    #         return data
    #     except FileNotFoundError:
    #         print(f"File not found: {file}")
    def get_aaa_random(self, rangemin, rangemax):
        mi = 10
        if rangemax < 1:
            return random.uniform(rangemin, rangemax)
        #bitmax = len(str(rangemax))
        #bitmin = len(str(rangemin))
        bitmin = int(math.log10(rangemin)) if rangemin > 0 else -1
        bitmax = int(math.log10(rangemax))
        if bitmin > bitmax:
            print(f"Warning: Invalid bit range (bitmin={bitmin}, bitmax={bitmax}).")
            return rangemin
        # I assume that the maximum is always an order of magnitude higher than the minimum
        choose_bit = random.randint(bitmin, bitmax)
        #minvalue = max(rangemin, (pow(mi, choose_bit-1)-1))
        #maxvalue = min(rangemax, pow(mi, choose_bit))
        minvalue = max(10 ** choose_bit, rangemin)
        maxvalue = min(10 ** (choose_bit + 1), rangemax)
        try:
            scale = 100
            value = random.randint(int(minvalue * scale), int(maxvalue * scale)) / scale
            #value = random.randint(minvalue, maxvalue)
            #value = random.uniform(minvalue, maxvalue)
            return value
        except ValueError as e:
            print(f'"Error in get_a_random: minvalue={minvalue}, maxvalue={maxvalue}')
            return 0 # fix: 0/1

    def get_a_random(self, rangemin, rangemax):
        if isinstance(rangemax, Decimal) and rangemax < Decimal('1'):
            rand_float = random.random()
            return rangemin + (rangemax - rangemin) * Decimal(str(rand_float))
        if rangemax < 1:
            return random.uniform(float(rangemin), float(rangemax))

        scale = 100
        if rangemax <= 0:
            abs_min = abs(rangemin)
            abs_max = abs(rangemax)
            bitmin = int(math.log10(abs_min)) if abs_min >= 10 else 0
            bitmax = int(math.log10(abs_max)) if abs_max >= 10 else 0
            choose_bit = random.randint(bitmax, bitmin) if bitmax <= bitmin else bitmax
            min_abs = max(10 ** choose_bit, abs_max)
            max_abs = min(10 ** (choose_bit + 1), abs_min)
            try:
                return -random.randint(min_abs, max_abs) / scale
            except ValueError:
                return (-abs_min - abs_max) / 2 / scale

        elif rangemin < 0:
            if random.choice([True, False]):
                abs_min = abs(rangemin)
                bitmin_neg = int(math.log10(abs_min)) if abs_min >= 10 else 0
                choose_bit = random.randint(0, bitmin_neg)
                max_abs = min(10 ** (choose_bit + 1), abs_min)
                min_abs = max(10 ** choose_bit, 1)
                try:
                    value = -random.randint(min_abs, max_abs) / scale
                except ValueError:
                    value = -abs_min / scale
            else:
                bitmax_pos = int(math.log10(rangemax)) if rangemax >= 10 else 0
                choose_bit = random.randint(0, bitmax_pos)
                min_val = max(10 ** choose_bit, 0)
                max_val = min(10 ** (choose_bit + 1), rangemax)
                try:
                    value = random.randint(min_val, max_val) / scale
                except ValueError:
                    value = rangemax / scale
            return value

        else:
            bitmin = int(math.log10(rangemin)) if rangemin >= 10 else 0
            bitmax = int(math.log10(rangemax)) if rangemax >= 10 else 0
            choose_bit = random.randint(bitmin, bitmax)
            minvalue = max(10 ** choose_bit, rangemin)
            maxvalue = min(10 ** (choose_bit + 1), rangemax)
            try:
                return random.randint(int(minvalue * scale), int(maxvalue * scale)) / scale
            except ValueError:
                return (rangemin + rangemax) / 2 / scale

    def get_random_value(self, row):
        increment = row['Increment']
        range_min = row['Range_Min']
        range_max = row['Range_Max']
        value = row['Value']

        if increment in ['B', 'V']:
            if value != 'N':
                #values = eval(value)
                values = ast.literal_eval(value) #more secure
                if values:
                    return random.choice(values)
                else:
                    return random.randint(0, 10)
            else:
                return random.randint(0, 100)
        elif increment == 'N':
            # ADSB_LIST_RADIUS,N,0,100000,N
            if range_min != 'N' or range_max != 'N':
                range_min = self.rangemin if range_min == 'N' else Decimal(str(range_min))
                range_max = self.rangemax if range_max == 'N' else Decimal(str(range_max))
                return self._random_choice_n(range_min, range_max)
            else:
                #return random.uniform(self.rangemin, self.rangemax)
                #return random.randint(self.rangemin, self.rangemax)
                return self.get_a_random(self.rangemin, self.rangemax)
        else:
            # range_min = float(range_min)
            # range_max = float(range_max)
            # increment = float(increment)
            range_min = self.rangemin if range_min == 'N' else Decimal(str(range_min))
            range_max = self.rangemax if range_max == 'N' else Decimal(str(range_max))
            increment = self.increment if increment == 'N' else Decimal(str(increment))
            return self._random_choice(range_min, range_max, increment)

    def _random_choice(self, range_min, range_max, increment):
        # Memory-fuzz: 20% chance to ignore range bounds entirely
        if random.random() < 0.20:
            return float(random.choice([-1, 0, 255, 65535, -32768,
                         max(1, int(range_max)) * random.randint(2, 100)]))

        choice = random.choices(
            population=[range_min, range_max, 'between'],
            weights=[0.2, 0.2, 0.6],
            k=1
        )[0]

        if choice == 'between':
            steps = int((range_max - range_min) // increment)
            random_step = random.randint(0, steps)
            return range_min + random_step * increment

        return choice

    def _random_choice_n(self, range_min, range_max):
        # Memory-fuzz: 20% chance to ignore range bounds entirely
        if random.random() < 0.20:
            return float(random.choice([-1, 0, 255, 65535, -32768,
                         max(1, int(range_max)) * random.randint(2, 100)]))

        choice = random.choices(
            population=[range_min, range_max, 'between'],
            weights=[0.1, 0.1, 0.8],
            k=1
        )[0]

        if choice == 'between':
            random_step = self.get_a_random(range_min, range_max)
            return random_step
        return choice

    # ---- Memory-fuzzing: params likely to trigger SIGSEGV when out-of-bounds ----
    MEMORY_DANGER_PATTERNS = [
        '_ID', '_INDEX', '_CHANNEL', '_FUNCTION', '_SRC', '_RECV_ID',
        '_MASK', '_IMU', '_GYR_ID', '_ACC_ID', '_TYPE', '_ORIENT',
        '_CUST_ROT', '_H_SW', '_GPIO', '_ALT_SOURCE', '_ENABLE_MASK',
        '_FS_MSK', '_3DMASK', '_BDMASK', '_RVMASK', '_FTW_MASK',
        '_VOLZ_MASK', '_IMU_MASK', '_GSF_RUN', '_GSF_USE',
        '_PRX', '_RNGFND', '_RPM', '_SERVO_BLH', '_STOP_PIN',
    ]
    # Flight-critical params: must stay in valid range for SITL to arm/fly
    MEMORY_SAFE_PATTERNS = [
        'ARMING_', 'DISARM_', 'FS_GCS_', 'FS_THR_', 'FRAME_CLASS',
        'SYSID_', 'BRD_SAFETY', 'MOT_PWM_TYPE', 'SCHED_LOOP_RATE',
    ]
    MEMORY_FUZZ_PROBABILITY = 0.55  # 55% chance to go out-of-bounds

    @staticmethod
    def _is_memory_danger(param_name: str) -> bool:
        for pat in RuntimeDictionary.MEMORY_DANGER_PATTERNS:
            if pat in param_name:
                for safe in RuntimeDictionary.MEMORY_SAFE_PATTERNS:
                    if safe in param_name:
                        return False
                return True
        return False

    @staticmethod
    def _gen_oob_value(param_info: dict) -> float:
        """Generate an out-of-bounds value designed to trigger SIGSEGV"""
        range_min = param_info.get('Range_Min', '0')
        range_max = param_info.get('Range_Max', '1000')
        try:
            rmin = int(float(str(range_min))) if str(range_min) != 'N' else 0
            rmax = int(float(str(range_max))) if str(range_max) != 'N' else 1000
        except (ValueError, TypeError):
            rmin, rmax = 0, 1000

        strategy = random.randint(0, 5)
        if strategy == 0:
            # Way over max (simulates buffer overflow / array OOB)
            return float(random.choice([rmax * 10, rmax * 100, 65535, 255, 32767]))
        elif strategy == 1:
            # Negative (simulates signed/unsigned confusion or negative index)
            return float(random.choice([-1, -2, -128, -32768, -rmin - 1]))
        elif strategy == 2:
            # Zero (simulates null pointer / division by zero)
            return 0.0
        elif strategy == 3:
            # Exactly one past max (off-by-one)
            return float(rmax + 1)
        elif strategy == 4:
            # Arbitrary large random
            return float(random.randint(0, 65535))
        else:
            # Negative large
            return float(-random.randint(1, 32768))

    def get_parameter_value(self, parameter_name):
        param_info = self.get_parameter(parameter_name)

        # Memory-fuzz mode: for danger params, go out-of-bounds
        if param_info is not None and self._is_memory_danger(parameter_name):
            if random.random() < self.MEMORY_FUZZ_PROBABILITY:
                return self._gen_oob_value(param_info)

        # Normal path
        if param_info is None:
            return self.get_a_random(self.rangemin, self.rangemax)
        return self.get_random_value(param_info)

class xyzData:
    def __init__(self):
        xdata = -35.36302630
        ydata = 149.16514103
        zdata = 584.3
        #: The 'home' point coordinates(x,y,z) should be obtained first after the Drone is initialized


# runtime_dict = RuntimeDictionary()
# for i in range(10):
#     print(runtime_dict.get_a_random(0,10000))
#
# #file = '../data/test.csv'
#
# runtime_dict.load_parameters()
# print(runtime_dict.get_parameter_value('ADSB_LIST_RADIUS'))

# param_info = runtime_dict.get_parameter('TELEM_DELAY')
# print(param_info)
# randomvalue = runtime_dict.get_random_value(param_info)
# print(randomvalue)

#------------------------------for test
mav = MavcmdDictionary()

param_set = mav.get_mav_param_set('MAV_CMD_NAV_GUIDED_ENABLE')
print(param_set)

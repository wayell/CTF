import json
import ctypes

lib = './crashMe.so'
funcs = ctypes.cdll.LoadLibrary(lib)

# void init()
init = funcs.init

# int setString(char *data);
setString = funcs.setString
setString.argtypes = [ctypes.c_char_p]
setString.restype = ctypes.c_int

# int getString();

getString = funcs.getString
getString.restype = ctypes.c_int

# int delString();
delString = funcs.delString
delString.restype = ctypes.c_int

# int setNum(uint64_t data);
setNum = funcs.setNum
setNum.argtypes = [ctypes.c_uint64]
setNum.restype = ctypes.c_int

# int getNum();
getNum = funcs.getNum
getNum.restype = ctypes.c_int

# int delNum();
delNum = funcs.delNum
delNum.restype = ctypes.c_int

init()
print("Hello! CrashMe!")

while True:
    argc = 0
    args = None
    received = input()
    try:
        received = json.loads(received)
        if received['callNum'] is None:
            raise Exception("callNum is None")

        callNum = received['callNum']
        if received['args'] is not None:
            argc = len(received['args'])
            args = received['args']
            print(f"argc: {argc}\nargs: {args}")
        
        if callNum == 1:
            if argc != 1:
                raise Exception("callNum 1 argc != 1")
            data = ctypes.c_char_p(args[0].encode())
            setString(data)

        elif callNum == 2:
            getString()

        elif callNum == 3:
            delString()

        elif callNum == 4:
            if argc != 1:
                raise Exception("callNum 4 argc != 1")
            setNum(ctypes.c_uint64(args[0]))

        elif callNum == 5:
            getNum()

        elif callNum == 6:
            delNum()

        else:
            raise Exception("Other Exceptions")
        print("Done")

    except json.decoder.JSONDecodeError:
        print("The input must be in JSON format")
        exit()
        
    except Exception as e:
        print(e)
        exit()


'''

undefined8 setString(void *param_1)

{
  void *pvVar1;
  void *pvVar2;
  
  if (str == (void *)0x0) {
    str = malloc(0x10);
    memset(str,0,0x10);
  }
  pvVar1 = str;
  if (*(long *)((long)str + 8) == 0) {
    pvVar2 = malloc(0x10);
    *(void **)((long)pvVar1 + 8) = pvVar2;
    memset(*(void **)((long)str + 8),0,0x10);
  }
  memcpy(*(void **)((long)str + 8),param_1,0xf);
  return 0;
}

undefined8 delString(void)

{
  undefined8 uVar1;
  
  if (str == (void *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    free(*(void **)((long)str + 8));
    free(str);
    uVar1 = 0;
  }
  return uVar1;
}

undefined8 getString(void)

{
  undefined8 uVar1;
  
  if (str == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    printf("string @ %s\n",*(undefined8 *)(str + 8));
    uVar1 = 0;
  }
  return uVar1;
}


'''
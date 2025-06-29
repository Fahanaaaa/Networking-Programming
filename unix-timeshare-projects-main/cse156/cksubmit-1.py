#!/usr/bin/env python3
#!/usr/bin/env python

# eg
# python3 ./cksubmit.py /tmp/dbg_/x.tgz myweb myserv
# ./cksubmit.py sub/name1_44350_6651200_name2-lab2.tar.gz myclient myserver

import os
import glob
import sys
import socket, struct
import subprocess
import string
import shutil

def getFileSize(f):
    maxsz = 2000000
    file_size = os.stat('%s' % f)
    sz = file_size.st_size
    print('Size of file ', f, ':', sz, 'bytes')
    if sz > maxsz :
        print(f'FAILED: file {f} has a large size {sz} (max is {maxsz})')
        print('Remove binary or data files from the archive file')
        sys.exit(1)


def findFile(topdir, f):
    runout = subprocess.run(['find', topdir, '-name', f], 
                            stdout=subprocess.PIPE, text=True)        
    myf = runout.stdout.strip()
    #print(myf)

    for l in myf.splitlines() : 

        myl2 = l.split('/')
        # ['', 'tmp', 'tmp.PXQsChJOqZ', 'namex', 'bin', ffile]
        #print(myl2)
        dirlevel = 5
        if len(myl2) < dirlevel : continue

        if f == myl2[dirlevel] :
            print('OK: found binary file: %s' % l)
            return

        if f != myl2[dirlevel] :
            print('FAILED: Incorrect depth for file: %s' % l)
            sys.exit(1)

    print('FAILED: no binary file found for %s' % f)
    sys.exit(1)



if __name__ == "__main__":

    # for now check for upto only two binaries
    argvlen = len(sys.argv)
    if argvlen <= 2 or argvlen > 4 :
        #print('Usage: %s TARGZFILE BINAPP1 [... BINAPP2]' % sys.argv[0])
        print('Usage: %s TARGZFILE BINAPP1 [BINAPP2]' % sys.argv[0])
        sys.exit(0)

    arg1 = sys.argv[1]
    exec1 = sys.argv[2]
    exec2 = None
    if len(sys.argv) == 4 :
        exec2 = sys.argv[3]

    getFileSize(arg1)


    # check archive is gzip
    runout = subprocess.run(["file", arg1], 
                            stdout=subprocess.PIPE, text=True)
    rc = runout.returncode
    #print('return code %s : %s' % (rc, runout))
    out1 = str(runout.stdout)
    # print(out1)

    # x: cannot open (No such file or directory)
    if 'cannot open' in out1 : 
        print('Archive file %s not found' % arg1)
        sys.exit(1)

    if not 'gzip' in str(out1) :
        print('Archive file %s is not gzip' % arg1)
        sys.exit(1)


    #runout = subprocess.run(["tar", "tvzf", arg1], stdout=subprocess.PIPE)
    #print(runout)
    #out1 = runout.stdout

    runout = subprocess.run(['mktemp', '-d'], stdout=subprocess.PIPE)    
    tmpdir1 = runout.stdout.decode('utf-8').strip()
    #tmpdir1 = tmpdir1.translate({ord(c): None for c in string.whitespace})
    #print('temp dir %s' % tmpdir1)

    runout = subprocess.run(['tar', 'xvzf', arg1, '-C', tmpdir1], 
                            stdout=subprocess.PIPE)    
    #print(runout)
 
    # find Makefile under tempdir
    # find /tmp/tmp.dlon42rvvv/ -name Makefile
    # one level under tmp dir
    # /tmp/tmp.dlon42rvvv/x/Makefile 
    runout = subprocess.run(['find', tmpdir1, '-name', 'Makefile'], 
                            stdout=subprocess.PIPE, text=True)        
    mymake = runout.stdout.strip()
    if mymake : 
        #print('mymake: "%s"' % mymake)

        lines = mymake.split()
        if len(lines) > 1 :
            print('FAILED: more than one Makefile found: "%s"' % lines)
            sys.exit(1)

        mymake2 = mymake.split('/')
        #print(mymake2)  # array
        if 'Makefile' != mymake2[4] :
            print('FAILED: incorrect depth for Makefile: %s' % mymake)
            sys.exit(1)

    topdir = '/'.join(mymake.split('/')[0:4])
    print('Top working directory %s' % topdir)

    # clean binary directory
    print('Removing * in directory %s/bin' % topdir)
    files = glob.glob('%s/bin/*' % topdir)
    for f in files :
        try:
            os.remove(f)
        except OSError as e :
            print("Error: %s : %s" % (f, e.strerror))
    print('Listing directory %s/bin' % topdir)
    list_files = subprocess.run(['ls', '-l', 'bin'],
                                cwd=topdir)


    # make the binaries
    print('Doing make using %s' % mymake)

    #runout = subprocess.run(['make', exec1], cwd=topdir,
    runout = subprocess.run(['make'], cwd=topdir,
                            stdout=subprocess.PIPE, text=True)        
    domake = runout.stdout.strip()

    # check make succeeded

    # check binary location
    findFile(topdir, exec1)  
    if exec2 :
        findFile(topdir, exec2)  

    # remove working tmp directory
    #'''
    folddir = '/'.join(mymake.split('/')[0:3])
    print('Removing temp folder directory %s' % folddir)
    try:
        # os.rmdir(folddir)
        shutil.rmtree(folddir)
    except OSError as e :
        print("Error: %s : %s" % (folddir, e.strerror))
    #'''

print('GOOD TO GO!')
sys.exit(0)

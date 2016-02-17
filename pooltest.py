from multiprocessing import Process, Lock

def f(i,j):

    print 'hello world', i,j



if __name__ == '__main__':
    a=[1,2,3]
    b=[4,5,6]
    c=extend(a,b)
    print c

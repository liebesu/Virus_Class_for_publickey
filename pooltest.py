from multiprocessing import Process, Lock

def f(i,j):

    print 'hello world', i,j


if __name__ == '__main__':


    for num in range(10):
        Process(target=f, args=( num,num)).start()
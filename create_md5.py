__author__ = 'liebesu'
import md5
import time
filename=time.strftime('%Y-%m-%d %H:%M:%S')
m=md5.md5()
f=open(filename,'w')
chars=[
                '0','1','2','3','4','5','6','7','8','9',
                'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            ]
base=len(chars) #62
end=len(chars)**4
for i in range(0,end):
    n=i
    ch0=chars[n%base]
    n=n/base
    ch1=chars[n%base]
    n=n/base
    ch2=chars[n%base]
    n=n/base
    ch3=chars[n%base]
    letter=ch3+ch2+ch1+ch0
    m.update(letter)
    md532=m.hexdigest()
    f.write(md532+'\n')
f.close()



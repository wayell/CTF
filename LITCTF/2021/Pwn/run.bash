i=30
while [ $i -ne 40 ]
do
        i=$(($i+1))
        python gets.py $i | nc gets.litctf.live 1337
        echo $i
done

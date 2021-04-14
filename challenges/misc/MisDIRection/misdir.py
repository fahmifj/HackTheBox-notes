fileName = "dir.txt"
arrList = []
key = []
data = []

## Open file, separate by lines, fill it to content
with open(fileName) as f :
    content = f.read().splitlines()

## Remove / for each line in content, store to arrList
for line in content:
    str = line[2:].replace('/', '')
    arrList.append(str)

## Separate element in arrList to key and data according to their position.
for element in arrList:
    key.append(int(element[1:]))
    data.append(element[0])

## Sort the keys and data numerically.
def sortIt(key, data):
    for i in range(len(key)):
        minKey = i
        for j in range(i+1, len(key)):
            if int(key[minKey]) > int(key[j]):
                minKey = j
        key[i], key[minKey] = key[minKey], minKey[i]
        data[i], data[minKey] = data[minKey], data[i]

sortIt(key, data)

## Get the flag
import base64

for i in range (len(key)):
    print("%d --> %s " %(key[i], data[i]))
    flag = flag + data[i]

print("flag : is ", end="")
print(base64.b64decode(flag))
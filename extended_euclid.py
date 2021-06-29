
def ex_ec(b, m):
    print("A1\tA2\tA3\tB1\tB2\tB3\tT1\tT2\tT3")
    a1,a2,a3 = 1,0,m
    b1,b2,b3 = 0,1,b
    while True:
        
        if b3 == 0:
            print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(a1,a2,a3,b1,b2,b3,t1,t2,t3))
            print("No modular inverse")
            return a3
        if b3 == 1:
            print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(a1,a2,a3,b1,b2,b3,t1,t2,t3))
            print(b2," is the modular inverse")
            return b3
        q = int(a3 / b3)
        t1,t2,t3 = a1-q*b1,a2-q*b2,a3-q*b3
        print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(a1,a2,a3,b1,b2,b3,t1,t2,t3))
        a1,a2,a3 = b1,b2,b3
        b1,b2,b3 = t1,t2,t3



def fastExpMod(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result


def dec2bin(num):
    l = []
    if num < 0:
        return '-' + dec2bin(abs(num))
    while True:
        num, remainder = divmod(num, 2)
        l.append(str(remainder))
        if num == 0:
            return ''.join(l[::-1])

def Convert(string):
    list1=[]
    list1[:0]=string
    return list1

def ini_al(alb = "ABCDEFGHIJKLMNOP"):
    al = dict()
    tmp = Convert(alb)
    i = 0
    for str in tmp:
        al[str] = i
        i += 1
    return  al

def ini_key(alb, key = "BCDEFGHIJKLMNOPA"):
    k = alb.keys()
    keye = dict()
    for i,j in zip(k, Convert(key)):
        keye[i] = j
    return keye

def cbc(iv, plaintext,alb, key):
    result = []
    pl = Convert(plaintext)
    reverse_alb = {v:k for k,v in alb.items()} # 反接
    for i in range(len(pl)):
        id_iv = alb[iv]
        id_plain = alb[pl[i]]
        new_id = id_iv ^ id_plain       
        new_text = reverse_alb[new_id]
        cipher_text = key[new_text]
        print("{}({}) xor {} = {}({}), E({}) = {}".format(iv, bin(id_iv), bin(id_plain), bin(new_id), new_text, new_text, cipher_text ) )
        result.append(cipher_text)
        iv = cipher_text
    return "".join(result)


def cfb(iv, plaintext, alb, key):
    result = []
    pl = Convert(plaintext)
    reverse_alb = {v:k for k,v in alb.items()} # 反接
    for i in range(len(pl)):
        id_plain = alb[pl[i]]
        cipher_text = key[iv]
        id_cipher = alb[cipher_text]
        new_id = id_cipher ^ id_plain
        new_text = reverse_alb[new_id]
        print("E({}) = {}, {} xor {} = {}({})".format( iv, cipher_text, bin(id_cipher), bin(id_plain), bin(new_id), new_text )) 
        result.append(new_text)
        iv = new_text
    return "".join(result)

def ofb(iv, plaintext, alb, key):
    result = []
    pl = Convert(plaintext)
    reverse_alb = {v:k for k,v in alb.items()} # 反接
    for i in range(len(pl)):
        id_plain = alb[pl[i]]
        cipher_text = key[iv]
        id_cipher = alb[cipher_text]
        print("E({}) = {}".format(iv, cipher_text), end=" ")
        iv = cipher_text
        new_id = id_cipher ^ id_plain       
        new_text = reverse_alb[new_id]
        print("{} xor {} = {}({})".format(bin(id_cipher), bin(id_plain), bin(new_id), new_text))
        result.append(new_text)
    return "".join(result)

def counter(iv, plaintext, alb, key):
    result = []
    pl = Convert(plaintext)
    reverse_alb = {v:k for k,v in alb.items()} # 反接
    for i in range(len(pl)):
        iv_text = reverse_alb[iv]
        cipher_text = key[iv_text]
        id_cipher = alb[cipher_text]
        id_plain = alb[pl[i]]
        new_id = id_plain ^ id_cipher
        new_text = reverse_alb[new_id]
        print("E({}) = {}, {} xor {} = {}({})".format(iv, cipher_text, bin(id_cipher), bin(id_plain), bin(new_id), new_text))
        iv += 1
        result.append(new_text)
    return "".join(result)

def cbc_decrypt(iv, cipher_text, alb, key):
    result = []
    ct = Convert(cipher_text)
    reverse_alb = {v:k for k,v in alb.items()}
    reverse_key = {v:k for k,v in key.items()}
    for i in range(len(ct)):
        temp = ct[i]
        pl = reverse_key[ct[i]]
        id_pl = alb[pl]
        id_iv = alb[iv]
        id_plain = id_pl ^ id_iv
        plain_text = reverse_alb[id_plain]
        print("D({}) = {}, {} xor {} = {}({})".format(temp, pl, id_pl, id_iv, id_plain, plain_text))
        iv = temp
        result.append(plain_text)
    return "".join(result)


def cbc_decrypt(iv, cipher_text, alb, key):
    result = []
    ct = Convert(cipher_text)
    reverse_alb = {v:k for k,v in alb.items()}
    reverse_key = {v:k for k,v in key.items()}
    for i in range(len(ct)):
        pl = key[iv]
        pl_id = alb[pl]
        ct_id = alb[ct[i]]
        
        new_id = pl_id ^ ct_id
        new_text = reverse_alb[new_id]
        print("E({}) = {}, {} xor {} = {}({})".format(iv, pl, pl_id, ct_id, new_id, new_text))
        iv = ct[i]
        result.append(new_text)

    return "".join(result)

def ofb_decrypt(iv, cipher_text, alb, key):
    result = []
    ct = Convert(cipher_text)
    reverse_alb = {v:k for k,v in alb.items()}
    reverse_key = {v:k for k,v in key.items()}
    for i in range(len(ct)):
        pl = key[iv]
        pl_id = alb[pl]
        ct_id = alb[ct[i]]
        new_id = pl_id ^ ct_id
        new_text = reverse_alb[new_id]
        print("E({}) = {}, {} xor {} = {}({})".format(iv, pl, pl_id, ct_id, new_id, new_text))
        iv = pl
        result.append(new_text)

    return "".join(result)

def counter_decrypt(iv, cipher_text, alb, key):
    result = []
    ct = Convert(cipher_text)
    reverse_alb = {v:k for k,v in alb.items()} # 反接
    for i in range(len(ct)):
        iv_text = reverse_alb[iv]
        cipher_text = key[iv_text]
        id_cipher = alb[cipher_text]
        id_ct = alb[ct[i]]
        new_id = id_ct ^ id_cipher
        new_text = reverse_alb[new_id]
        print("E({}) = {}, {} xor {} = {}({})".format(iv, cipher_text, bin(id_cipher), bin(id_ct), bin(new_id), new_text))
        iv += 1
        result.append(new_text)
    return "".join(result)

if __name__ == "__main__":
    
    alb = ini_al()
    key = ini_key(alb)
    print(key)
    print(alb)
    ci = counter(1, "IAMBOB", alb, key)
    pi = counter_decrypt(1, ci, alb, key)
    print(ci)
    print(pi)
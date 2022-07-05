---
title: Malware Analysis GandCrab Ransomware
date: 2022-07-04 11:32:00 +0700
categories: [MalwareAnalysis]
tags: [gandcrab, malwareanalysis]
toc: true
---


### Lời nói đầu
- Ở phân tích này mình sẽ tập trung phân tích mã độc GandCrab phiên bản 5.2, với hash: `017b236bf38a1cf9a52fc0bdee2d5f23f038b00f9811c8a58b8b66b1c756b8d6`, bạn đọc có thể tìm mẫu sample đó trên [**vx-underground**](https://samples.vx-underground.org/samples/Families/GandCrab/).

### General Information
- Sử dụng công cụ `ExeinfoPE`, mình thu được thông tin cơ bản sau:
    - Compiler: MSVC++.
    - Image: 32bit.

![infoPE](/assets/img/GandCrab_images/infoPE.png)

- Ngoài ra, ở section `.text`, cột `Stat` hiện kết quả `Crypted Maybe`, nhiều khả năng tại địa chỉ của section đó đã bị obfuscated.

![sstatPE](/assets/img/GandCrab_images/sstatPE.png)

### Obfuscated strings
- Các strings mà GandCrab sử dụng đều đã bị mã hoá. Hàm giải mã wide strings sẽ nhận 4 tham số truyền vào:
    - Tham số thứ nhất: ARC4 Key.
    - Tham số thứ hai: size của ARC4 Key.
    - Tham số thứ ba: ARC4 Cipher, bắt đầu từ phần tử thứ 24.
    - Tham số cuối cùng: size ARC4 Cipher, phụ thuộc vào kết quả XOR của phần tử thứ 16 và phần tử thứ 20.

```c++
_BYTE *__cdecl sub_407563(int a1)
{
  return do_RC4(a1, 0x10u, (_BYTE *)(a1 + 24), *(_DWORD *)(a1 + 16) ^ *(_DWORD *)(a1 + 20));
}
```

- Tham số đầu vào `a1` của hàm `sub_407563` là một mảng bytes dài, tham số đó được gọi từ một hàm con và sử dụng thuật toán ARC4 để giải mã các mảng bytes.

```c++
_BYTE *__cdecl sub_407581(int a1, unsigned int a2, _BYTE *a3, int a4)
{
  int v4; // esi
  unsigned int i; // eax
  unsigned int j; // edi
  char v7; // bl
  int v8; // edi
  int v9; // esi
  int v10; // ebx
  char v11; // dl
  char v13[260]; // [esp+Ch] [ebp-104h]
  _BYTE *v14; // [esp+124h] [ebp+14h]

  LOBYTE(v4) = 0;
  for ( i = 0; i < 0x100; ++i )
    v13[i] = i;
  for ( j = 0; j < 0x100; ++j )
  {
    v7 = v13[j];
    v4 = (unsigned __int8)(v4 + *(_BYTE *)(j % a2 + a1) + v7);
    v13[j] = v13[v4];
    v13[v4] = v7;
  }
  v8 = a4;
  LOBYTE(v9) = 0;
  LOBYTE(v10) = 0;
  if ( !a4 )
    return a3;
  v14 = a3;
  do
  {
    v10 = (unsigned __int8)(v10 + 1);
    v11 = v13[v10];
    v9 = (unsigned __int8)(v9 + v11);
    v13[v10] = v13[v9];
    v13[v9] = v11;
    *v14++ ^= v13[(unsigned __int8)(v11 + v13[v10])];
    --v8;
  }
  while ( v8 );
  return a3;
}
```

- Mã giả trên có sự tương đồng với một project mà mình đã tìm được trên GitHub: [**ARC4 Implementation**](https://github.com/drFabio/RC4/blob/master/ARC4.cpp)

### Decrypt strings
- Với sự hỗ trợ của IDAPython, mình có thể viết script nhằm tự động hoá giải mã strings, full script mình đã public trên GitHub: [**Decrypt Strings**](https://github.com/MrEn1gma/GandCrab-Decrypt-String/blob/main/gandcrab_decrypt.py).

- Dưới đây là một phần của IDAPython script:

```python
ciphertext_list, addr_xrefs = GetCipherText("sub_407563")
for idx in range(len(ciphertext_list)):
    inp = [i for i in bytes.fromhex(ciphertext_list[idx])[::-1]]
    key = np.array(inp[:16], "<u1").tobytes()
    sizeCipher = inp[16] ^ inp[20]
    cipher = np.array(inp[24:24 + sizeCipher], "<u1").tobytes()
    arc4 = ARC4.new(key)
    out = arc4.decrypt(cipher)
    plaintext = [i for i in out]

    for j in range(len(plaintext)):
        chk = 0
        if(chk in plaintext):
            plaintext.remove(0) # Sau khi decrypt xong, bỏ các byte 0 để print ra chuỗi hoàn chỉnh        
    msg_output = "[" + str(hex(addr_xrefs[idx])) + "] | Encrypted string: 0x" + str(ciphertext_list[idx]) + " | Decrypted string: " + str("".join([chr(i) for i in plaintext]))
    msg_cmt_output = "Decrypted string: " + str("".join([chr(i) for i in plaintext]))
    idc.set_cmt(addr_xrefs[idx], msg_cmt_output, 0) # set comment tai ham do
    print(msg_output)
        
print("OK.")
```


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

### Strings Obfuscaion
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

- Kết quả sau khi thực hiện script, có tất cả 158 strings đã được giải mã:

![IDAPythonScript](/assets/img/GandCrab_images/idapython_script.png)

### Random Extension
- Mã độc thực hiện quá trình tạo extension ngẫu nhiên gồm các bước:
    - Gọi hàm API `CryptGenRandom` sau đó tính toán độ dài chuỗi ngẫu nhiên nằm trong khoảng được đã được xác định.
    - 

### Collect victim's information
- Dựa trên kết quả sau khi thực hiện decrypt strings, dưới đây là danh sách các strings đặc biệt được sử dụng để lấy thông tin từ máy nạn nhân:
    - pc_user: Username của máy nạn nhân.
    - pc_name: Tên máy nạn nhân.
    - pc_group: `WORKGROUP` / `undefined`
    - av: Anti-Virus.
    - pc_lang: PC Language.
    - pc_keyb: Loại bàn phím.
    - os_major: Tên hệ điều hành.
    - os_bit: `x32`/`x64`.
    - ransom_id: ID của ransomware.
    - hdd: `UNKNOWN`/`NO_ROOT_DIR`/`REMOVABLE`/`FIXED`/`REMOTE`/`CDROM`/`RAMDISK`
    - ip: Địa chỉ IP của máy nạn nhân.
    - version: Phiên bản mã độc GandCrab.

- Hàm `decrypt_API` sẽ deobfuscate lần lượt `RegQueryValue` và `RegCloseKey`, mục đích để thực hiện lấy giá trị từ Key Value.

```c++
int __stdcall do_Registry_Keys(int a1, int a2, int a3, int a4, int a5, int a6)
{
  int (__stdcall *v6)(int, int, _DWORD, int, int *); // eax
  int v7; // edi
  int v8; // esi
  int (__stdcall *v9)(int, int, _DWORD, _DWORD, int, int *); // eax

  v6 = (int (__stdcall *)(int, int, _DWORD, int, int *))decrypt_API(5, 0xAAD67FEE);// RegQueryValue
  v7 = 0;
  if ( v6(a1, a2, 0, 131097, &a6) )
    return 0;
  v8 = a6;
  a2 = a5;
  v9 = (int (__stdcall *)(int, int, _DWORD, _DWORD, int, int *))decrypt_API(5, 0x1802E7DE);// RegCloseKey
  if ( !v9(v8, a3, 0, 0, a4, &a2) )
    v7 = 1;
  sub_401AFB(a6);
  return v7;
}
```

### PC DATA
- Cách hoạt động
    - Những dữ liệu sau khi mã độc thu thập được, nối các chuỗi dữ liệu bằng dấu `&` thành một chuỗi lớn và lưu vào biến `general_in4_PC_DATA`. Sau đó bắt đầu mã hoá chúng bằng thuật toán ARC4 với key: `.oj=294~!z3)9n-1,8^)o((q22)lb$`

```c++
int __cdecl encrypt_PC_DATA(int a1, int a2)
{
  void *v2; // esi
  int v3; // eax
  char v5[256]; // [esp+4h] [ebp-100h] BYREF

  v2 = VirtualAlloc(0, 0x20u, 0x3000u, 4u);
  sub_4074C8(v2, ".oj=294~!z3)9n-1,8^)o((q22)lb$");// key: .oj=294~!z3)9n-1,8^)o((q22)lb$
  if ( !v2 )
    return a1;
  sub_40C70B(v5, 0, 0x100u);
  v3 = sub_405CA9(v2);
  start_ARC4(v5, v2, v3);
  ARC4_Decrypt(v5, a1, a2);
  VirtualFree(v2, 0, 0x8000u);
  return a1;
}
```
- Biến `general_in4_PC_DATA` sau khi mã hoá và vùng nhớ lưu các bytes đã bị mã hoá:

![enc1](/assets/img/GandCrab_images/genPCDATA.png)
![enc2](/assets/img/GandCrab_images/encPCDATA.png)

- Ngoài ra, biến `general_in4_PC_DATA` được gọi từ hàm `export_GANDGRAB_key_and_info_PC`, nhằm export ra file có format là `%extension%-MANUAL.txt`
- Dựa vào pseudo-code trên, mình có thể viết lại script để giải mã `PC_DATA`:

```python
# Decrypt PC_DATA
print("\n--- PC_DATA ---")
pc_key = ".oj=294~!z3)9n-1,8^)o((q22)lb$".encode()
pc_cipher = b64decode("7ftDEgLb/ZS0lcmZbHM61I/J+AOoD+QKyw7LboogFHYeWLYCxZ+XYFtxBmDb9KHJOJDfAveVruDURWTIXHRKQxSaxLPQzr4SaOgCapOX2qbLGOIpU0uVIkugicQ2qivs7UgEXVJiDcF0iWP/gFL8WqBHGyOgMof74iZHO883kWa60KsRG/ofEubBktl3sqmHT/UeIK90f4NTA3Q0Aa7fDOtFnCOTB5ome7FLZ/fMCt27gAb2/52sUzN7xdxdWKoyoIWs5zhHRnLzMN2B2FCdeiqo6lrnnIaZ6V9BSTXO4zB9mPr7qICkGFwpU6i/RSEVcPfH0wpSWSCYtNWJJNBZBilqqMZrR7W3ZLHPmYGRj0eJP9/y/fM3LOXjXaO0r1pWo+YkTxTJi/a4L0V0svf5S0uz66BfoUfFwZ2CPDSx4yhFudDoMFoN6ieVyOmvqBxvfLwArtgyoy8F1fOlXDmW7qZ4Buw/gTuwIUyBb8YftNxTLWijqrjEwB/itTONKJOg3o3LWKn+7wkTvCmihYFNEr9E4CN7AJnhnNRKIBD1XUGeyfaMbJ0e1lo/q+RXezYEh3TGCu/rONcZPBaVdco=")
arc4 = ARC4.new(pc_key)
pc_output = arc4.decrypt(pc_cipher)
pc_plaintext = [i for i in pc_output]

for i in range(len(pc_plaintext)):
    pcchk = 0
    if(pcchk in pc_plaintext):
        pc_plaintext.remove(0)
        
print("".join([chr(i) for i in pc_plaintext]))
```


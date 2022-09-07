---
title: findtheflag.exe - defeating custom Self Modify with IDAPython
date: 2022-09-07 14:00:00 +0700
categories: [CTF, RE]
tags: [selfmodify, idapython, z3]     
---
# Lời nói đầu

Crackme trên do mình tình cờ đọc blog của anh m4n0w4r về writeup có trên [tut4you](https://forum.tuts4you.com/topic/37666-crackme-find-the-flag-by-extremecoders/). Bài này tuy dùng kỹ thuật khá là cổ điển nhưng ít nhiều nó giúp mình có thêm cái nhìn rõ hơn về kỹ thuật `Self Modify` mà tác giả đã vận dụng rất sáng tạo.

## Giới thiệu

* **Given files:** [findtheflag.exe](https://github.com/MrEn1gma/Writeups/raw/main/Unpack%20me%20if%20you%20can/findtheflag.exe)
* **Description**: You need to find the flag which will print the good boy message, Everything is allowed.
* **Category**: Reversing
* **Summary**: Tác giả sử dụng kỹ thuật `Self Modify` nhằm mã hoá từng phần của instruction sang các bytecode. Bằng cách sử dụng IDAPython, mình sẽ khôi phục lại các instruction về ban đầu.

## Phân tích binary
Phân tích hàm `main`, mình nhận thấy rằng IDA chỉ nhận diện được tới đoạn `popa` instruction, còn khúc sau mình nhận thấy nó không giống với instruction thông thường, khả năng cao nó là các bytecodes đã bị mã hoá.

![main_a](/assets/img/findtheflag_img/self_modify_main.png)

Đặt breakpoint tại `pusha (0x40103a)` and `popa (0x401055)`. Sau đó debug tới địa chỉ `0x401055`, nhận thấy rằng 1 phần đầu của bytecode đã được giải mã bằng thuật toán XOR. Tuy nhiên hay nhìn địa chỉ `0x40125a` tới địa chỉ `0x401275`, mình thấy rằng nó gần giống với block trên và nó sử dụng key xor tận 2 lần. Điều đó có nghĩa là, nếu như mình trace từ block thứ nhất sang block tiếp theo, các bytecode sẽ được giữ nguyên bởi vì 2 lần mã hoá/giải mã đều sử dụng chung key. Để giải thích rõ ràng hơn, mình đã mô phỏng lại cách hoạt động của Crackme này:

* Gọi `STAGE 1` là quá trình thực hiện 3 bước `Giải mã -> Thực thi code -> Mã hoá` của nhóm bytecodes thứ nhất (chú ý rằng bytecodes mà địa chỉ 0x401056 trở đi nó được chia thành từng nhóm nhỏ để thực hiện theo `STAGE`). Nếu mình debug tới STAGE thứ `N`, nghĩa là `N - 1` STAGE trước đó đã bị modified về các bytecodes ban đầu, hiểu nôm na rằng chương trình ngăn chặn không cho mình xem được full mã giả.

![main_b](/assets/img/findtheflag_img/flow_graph.jpg)

## Chiến thuật
**Nhận xét:** Đối với bài này, nếu luớt hết các bytecodes ở dưới, mình thấy có khá là nhiều, chưa kể mình cũng không biết chính xác Crackme này thực hiện bao nhiêu STAGE nên việc debug trong trong trường hợp này là không hiệu quả. Vì vậy sẽ thuận tiện hơn nếu như sử dụng IDAPython để decrypt các bytecodes trên. Vậy thì, để làm được điều này mình cần phải có những thông tin sau:
* Size của nhóm bytecodes: dựa vào pattern `B9`, tương ứng với `mov ecx`. Từ đó sử dụng hàm `get_operand_value` để lấy giá trị của operand thứ 1 cũng chính là giá trị của size bytecode.
* Key xor của bytecodes: dựa vào pattern `80 34 0E` chính là `xor`. Cách lấy giá trị keyxor cũng làm tương tự như ở bước trên.
* Size của nhóm pusha tới popa: dễ dàng nhận thấy có 28 bytes.
* Bytecodes và địa chỉ tương ứng với các bytes: sau khi có size của nhóm bytecodes và Size của nhóm pusha tới popa thì việc tìm các bytecodes sẽ trở nên dễ dàng hơn. Để ý rằng, bytecodes bắt đầu từ địa chỉ `0x401056`, mình sẽ tính được các bytecode kế tiếp bằng cách `lấy địa chỉ đầu tiên của nhóm bytecodes + size của nhóm bytecodes + 56`, với 56 là 28 bytes của nhóm pusha/popa + 28 bytes kế tiếp của nhóm pusha/popa đó.
Sau đó dùng hàm ida_bytes.patch_bytes để thay thế bằng giá trị của bytecode xor với keyxor tương ứng và nop luôn các block có pusha tới popa.

## Tới giờ thực hiện rồi !!!
Tìm các nhóm bytecodes:

```python
def getGroupOfBytes(list_size):
    start_addr = idaapi.inf_get_main() + 0x56 # start bytecodes
    list_bytes = []
    list_addrs = []
    for idx_size in list_size:
        list_addrs.append(start_addr)
        out = [i for i in ida_bytes.get_bytes(start_addr, idx_size)]
        list_bytes.append(out)
        start_addr = start_addr + idx_size + 56
        
    return list_bytes, list_addrs
```

Tìm size của bytecode và keyxor:

```python
def search_list_pattern(startEA, endEA, pattern):
    list_addr = []
    while(startEA < endEA):
        out = find_binary(startEA, endEA, pattern, 16, SEARCH_DOWN)
        if((out not in list_addr) and (out != ida_idaapi.BADADDR) and (idc.get_operand_value(out, 1) < 0xffff)):
            list_addr.append(out)
        startEA += 1
    return list_addr

def getValueFromAddr(list_addr):
    out = []
    out1 = []
    for idx_addr in list_addr:
        out.append(idc.get_operand_value(idx_addr, 1))
        
    for i in range(0, len(out), 2): # each stages do dec/enc at the same stage, dec/enc are used same size of bytes. So I remove one in each stages
        out1.append(out[i])
    return out1

list_size_of_bytecodes = getValueFromAddr(search_list_pattern(main_startEA, main_endEA, opcode_of_size_bytecodes))
list_key_xor = getValueFromAddr(search_list_pattern(main_startEA, main_endEA, opcode_xor))
```
Full script mình để ở đây: [unpacker](https://github.com/MrEn1gma/Writeups/blob/main/Unpack%20me%20if%20you%20can/unpacker.py)

## Phân tích file decrypted (unpackeeeer.exe)
Sau khi chạy script xong, mình đã có được mã giả tương đối đẹp.

![main_c](/assets/img/findtheflag_img/before_dec_main.png)

Đối với mình thì mã giả trên chưa thật sự "đẹp" cho lắm, cho nên mình đã chỉnh lại cái size của `char Buffer[4]` thành `char Buffer[31]` (vì nhìn vào input ta thấy được hàm gets lấy tối đa là 31 bytes), lúc này mã giả trông đẹp hơn.

![main_c](/assets/img/findtheflag_img/after_dec_main.png)

Về tổng quan chương trình mới là 1 đống hệ phương trình tuyến tính, mình không mất quá nhiều thời gian để giải tay, trực tiếp quăng nó vô z3 solver và giải ra nghiệm và grep lại thành flag.

Full script solve [solve.py](https://github.com/MrEn1gma/Writeups/blob/main/Unpack%20me%20if%20you%20can/solve.py)

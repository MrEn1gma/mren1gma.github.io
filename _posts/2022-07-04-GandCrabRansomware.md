---
title: Malware Analysis GandCrab Ransomware
date: 2022-07-04 11:32:00 +0700
categories: [MalwareAnalysis]
tags: [gandcrab, malwareanalysis]
toc: true
---


### Lời nói đầu
- Ở phân tích này mình sẽ tập trung phân tích mã độc GandCrab phiên bản 5.2, với hash: `017b236bf38a1cf9a52fc0bdee2d5f23f038b00f9811c8a58b8b66b1c756b8d6`, các bạn có thể tìm mẫu sample trên `vx-underground`.

### General Information
* Sử dụng công cụ `ExeinfoPE`, mình thu được thông tin cơ bản sau:
- Compiler: MSVC++.
- Image: 32bit.

* Ngoài ra, ở cột `Stats` trong chức năng `Section Viewer` cho mình biết được tại Virtual Offset `00001000` hiện kết quả là `Crypted Maybe`. Nhiều khả năng mã độc có sử dụng obfuscation nhằm che giấu những dữ kiện quan trọng.


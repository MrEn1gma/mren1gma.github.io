---
title: Coconut - ASCIS CTF 2022
date: 2022-10-19 20:00:00 +0700
categories: [CTF, RE]
tags: [Obfuscation, ascis]
---
# Lời nói đầu

* Vòng loại giải Sinh Viên An Toàn Thông Tin ASEAN đã kết thúc vào ngày 15/10. Đó là ngày đáng nhớ của mình cũng như các bạn khác tham gia vào ngày hôm đó, team mình - `th++` đã cố gắng giành được giải Khuyến Khích. Cảm xúc của mình lúc đó có buồn, có vui. Nhưng ít nhất mình cũng đã tận hưởng những ngày tháng cùng đám bạn tham gia SVATTT với tư cách là sinh viên năm cuối ĐH.

* Bài `coconut` mình đã không kịp giải ra vào thời điểm đó, nhưng mình đã cố gắng giải bài này và cuối cùng mình cũng đã hoàn thành. Trước khi đi vào phần writeup, mình xin cảm ơn em `@mochi753` và `@EaZyQ` đã hỗ trợ anh giải ra được bài đó.

## Giới thiệu

* **Given files:** [coconut.exe](https://github.com/MrEn1gma/Writeups/raw/main/ASCIS/2022/Coconut/Coconut.exe)
* **Category**: Reversing
* **Summary**: Crackme được viết bằng c# và sử dụng kỹ thuật che giấu đi code thật (không rõ chi tiết cái technique đó), bằng việc decrypt toàn bộ các hàm bị obfuscation. Sau đó reverse lại cái Crypto đó, mình tìm được key của flag1, flag thứ 2 phụ thuộc vào stack frame để cho ra key đúng, từ đó mình tìm ra được flag còn lại.

## Tổng quan

Nhìn tổng quan toàn bộ các hàm của binary, dễ dàng nhận ra rằng tất cả các hàm đều bị obfuscated, ngoại trừ hàm `coconut_10` là nơi lưu trữ các giá trị nhằm phục vụ cho việc deobfuscate sau khi crackme được thực thi.

```c#
internal class Program
{
	// Token: 0x06000017 RID: 23 RVA: 0x00002FF4 File Offset: 0x000011F4
	private static void Main(string[] args)
	{
		Coconut.coconut_10();
		string text = Coconut.coconut_28();
		if (Coconut.coconut_25(Coconut.coconut_15(text)))
		{
			Coconut.coconut_46(text);
		}
	}
}
```

Phần `Deobfuscate` sẽ giải mã toàn bộ các hàm và tiếp tục phân tích.

## Deobfuscate

Mình lấy hàm `coconut_28` làm ví dụ: hàm này sử dụng để giải mã cái hàm `coconut_82`, nhưng do hàm `coconut_82` chưa được dnSpy nhận diện là 1 hàm, nên nó sẽ nhảy tới hàm `coconut_25` để decode. Để ý là có `coconut_meat28` và `coconut_water28` được load vào.

Hàm `coconut_25`:

```c#
public static object coconut_25(InvalidProgramException e, object[] args, Dictionary<uint, int> m, byte[] b)
{
	int metadataToken = new StackTrace(e).GetFrame(0).GetMethod().MetadataToken;
	Module module = typeof(Program).Module;
	MethodInfo methodInfo = (MethodInfo)module.ResolveMethod(metadataToken);
	MethodBase methodBase = module.ResolveMethod(metadataToken);
	ParameterInfo[] parameters = methodInfo.GetParameters();
	Type[] array = new Type[parameters.Length];
	SignatureHelper localVarSigHelper = SignatureHelper.GetLocalVarSigHelper();
	for (int i = 0; i < array.Length; i++)
	{
		array[i] = parameters[i].ParameterType;
	}
	Type declaringType = methodBase.DeclaringType;
	DynamicMethod dynamicMethod = new DynamicMethod("", methodInfo.ReturnType, array, declaringType, true);
	DynamicILInfo dynamicILInfo = dynamicMethod.GetDynamicILInfo();
	MethodBody methodBody = methodInfo.GetMethodBody();
	foreach (LocalVariableInfo localVariableInfo in methodBody.LocalVariables)
	{
		localVarSigHelper.AddArgument(localVariableInfo.LocalType);
	}
	byte[] signature = localVarSigHelper.GetSignature();
	dynamicILInfo.SetLocalSignature(signature);
	foreach (KeyValuePair<uint, int> keyValuePair in m)
	{
		int value = keyValuePair.Value;
		uint key = keyValuePair.Key;
		int tokenFor;
		if (value >= 1879048192 && value < 1879113727)
		{
			tokenFor = dynamicILInfo.GetTokenFor(module.ResolveString(value));
		}
		else
		{
			MemberInfo memberInfo = declaringType.Module.ResolveMember(value, null, null);
			if (memberInfo.GetType().Name == "RtFieldInfo")
			{
				tokenFor = dynamicILInfo.GetTokenFor(((FieldInfo)memberInfo).FieldHandle, ((TypeInfo)((FieldInfo)memberInfo).DeclaringType).TypeHandle);
			}
			else if (memberInfo.GetType().Name == "RuntimeType")
			{
				tokenFor = dynamicILInfo.GetTokenFor(((TypeInfo)memberInfo).TypeHandle);
			}
			else if (memberInfo.Name == ".ctor" || memberInfo.Name == ".cctor")
			{
                tokenFor = dynamicILInfo.GetTokenFor(((ConstructorInfo)memberInfo).MethodHandle, ((TypeInfo)((ConstructorInfo)memberInfo).DeclaringType).TypeHandle);
			}
			else
			{
				tokenFor = dynamicILInfo.GetTokenFor(((MethodInfo)memberInfo).MethodHandle, ((TypeInfo)((MethodInfo)memberInfo).DeclaringType).TypeHandle);
			}
		}
		b[(int)key] = (byte)tokenFor;
		b[(int)(key + 1U)] = (byte)(tokenFor >> 8);
		b[(int)(key + 2U)] = (byte)(tokenFor >> 16);
		b[(int)(key + 3U)] = (byte)(tokenFor >> 24);
	}
	dynamicILInfo.SetCode(b, methodBody.MaxStackSize);
	return dynamicMethod.Invoke(null, args);
}
```

MetadataToken thực hiện load token nhằm lấy data của hàm `coconut_82`, sau đó thực hiện vòng lặp để nạp vào các section và tiến hành giải mã các byte của hàm `coconut_82`, cuối cùng thực thi chúng bằng method `dynamicMethod.Invoke(null, args)`.

* metataToken:

![metatdata](/assets/img/ASCIScoconut_img/photo_2022-10-21_10-27-46.jpg)

* Hàm giải mã:

```C#
b[(int)key] = (byte)tokenFor;
b[(int)(key + 1U)] = (byte)(tokenFor >> 8);
b[(int)(key + 2U)] = (byte)(tokenFor >> 16);
b[(int)(key + 3U)] = (byte)(tokenFor >> 24);
```

**Nhận xét:** hàm `coconut_25` chỉ thực hiện giải mã bằng cách dùng toán tử `shift right` lần lượt là 8, 16, 24, mình có thể viết script để thực hiện giải mã:

```python
def ASCIS_coconut_decrypt(meat, water):
    for i in range(len(meat)):
        water[meat[i][0]] = meat[i][1] & 0xff
        water[meat[i][0] + 1] = (meat[i][1] >> 8) & 0xff
        water[meat[i][0] + 2] = (meat[i][1] >> 16) & 0xff
        water[meat[i][0] + 3] = (meat[i][1] >> 24) & 0xff

    return water
```

Sau đó sửa các byte dựa trên địa chỉ của `water` tương ứng với hàm cần giải mã, trong trường hợp ở đây là `water28` có địa chỉ là `0x7bc + 21` với 21 là size của `water28`.

NOTE: để tìm chính xác địa chỉ của `water28`, mình sử dụng chức năng `Show Instructions in Hex Editor`.

Full script mình để ở đây: [deobfuscate_coconut](https://github.com/MrEn1gma/Writeups/blob/1e22e7dfb687829b0fbf2713c22e0779922c4b8e/ASCIS/2022/Coconut/decrypt.py)

## Phân tích coconut.exe (patched)

Sau khi decrypt xong, hàm `coconut_82` và các hàm khác đã được giải mã.

* Nhập key và read key.
```c#
public static string coconut_82()
{
	Console.Write("Enter key: ");
	return Console.ReadLine();
}
```

* Hàm xử lý input

```C#
public static string coconut_51(string s)
{
	return BitConverter.ToString(Encoding.Default.GetBytes(s)).Replace("-", "");
}
```

Quan sát hàm `coconut_51`, mình nhận thấy nó thực hiện 2 bước để check. Đầu tiên chúng sẽ convert các ký tự ASCII sang chuỗi số thập lục phân và xoá các ký tự `-` để thành 1 chuỗi hexstring. Tiếp tục đi vào hàm `coconut_52` để thực hiện check key.

![debug_value](/assets/img/ASCIScoconut_img/photo_2022-10-21_10-54-53.jpg)

* Hàm `coconut_52`:

```c#
public static bool coconut_52(string i)
{
	return BigInteger.Parse(i, NumberStyles.HexNumber) * Coconut.coconut_89(Coconut.water_01) % Coconut.coconut_89(Coconut.water_02) == Coconut.coconut_89(Coconut.water_03);
}
```

```c#
public static BigInteger coconut_98(byte[] b)
{
	string text = "";
	foreach (byte b2 in b)
	{
		if (b2 < 10)
		{
			text += ((char)(b2 + 48)).ToString();
		}
		else
		{
			text += ((char)(b2 + 87)).ToString();
		}
	}
	return BigInteger.Parse(text, NumberStyles.HexNumber);
}
```

Quan sát hàm `coconut_98`, chúng sẽ load lần lượt các giá trị `Coconut.water_01`, `Coconut.water_02`, `Coconut.water_03` để tính toán ra các số nguyên lớn và sau khi input được convert sang chuỗi hexstring, method `BigInteger` trong hàm `coconut_52` prase chuỗi hexstring thành số nguyên lớn. Sau đó thực hiện tính toán để check key.

**Nhận xét:** Một bài toán liên quan tới Crypto, tuy nhiên thì mình không đi sâu về phần giải thích mà chỉ đưa ra phần giải.

```txt
-- PROBLEM --
passwd * coconut_water01 % coconut_water02 = coconut_water03
=> passwd = (coconut_water03 * inverse(coconut_water01, coconut_water02)) % coconut_water02
```

* Thực hiện bằng python script

```python
passwd = long_to_bytes((ASCIS_coconut_52_BIGNUMBER(coconut_water03) * inverse(ASCIS_coconut_52_BIGNUMBER(coconut_water01), ASCIS_coconut_52_BIGNUMBER(coconut_water02))) % ASCIS_coconut_52_BIGNUMBER(coconut_water02))
```

Chạy file script trên, mình đã tìm ra được key: `Ytd_is_history_Tmr_is_a_mystery!`. Lúc này mình thử test trên powershell thì ra được thông báo dưới đây:

![error_flag](/assets/img/ASCIScoconut_img/photo_2022-10-21_13-33-41.jpg)

Tuy nhiên trong lúc chạy thì file `PANDA.png` đã được dump ra:

![flag1](/assets/img/ASCIScoconut_img/PANDA.jpg)

Như vậy mình đã có được 1 phần của flag: `ASCIS{7hat's_Why_7h3y_call_it`. Tuy nhiên phần còn lại của flag thì mình chưa biết, vì cái thông báo trên powershell lúc nãy đã cho mình biết được nhiệm vụ tiếp theo phải bypass được đoạn đó để tìm ra flag còn lại.

## Bypass the Time

Phân tích lại file sau khi đã deobfuscated, sau khi đã decrypt ra file `PANDA.jpg` bằng thuật toán AES, nó nhảy vào hàm `coconut_06` và tới hàm `coconut_60`:

```c#
public static void coconut_60()
{
	while (DateTime.Now.Year < 3022)
	{
		Console.WriteLine("Waiting for a thousand year.");
		Thread.Sleep(86400000);
	}
	Coconut.coconut_36();
}
```

Đoạn check chỉ kiểm tra năm hiện tại trên máy tính có lớn hơn 3022 hay không, ngược lại nó sẽ nhảy vào vòng lặp "vô tận". Để pass nó, bạn đọc có thể edit lại method và sửa dấu `<` thành `>`. Lưu lại và chạy file đã patched.

![error_flag2](/assets/img/ASCIScoconut_img/photo_2022-10-21_14-31-06.jpg)

Lần này mình đã dump ra được file `DRAGON_WARRIOR.png`, nhưng có gì đó không đúng....

Debug qua đoạn dump ra file `DRAGON_WARRIOR.png` cụ thể ở đây là hàm `coconut_16`, mình thấy nó in ra key: `Void coconut_63()System.String coconut_16()`

![debug2](/assets/img/ASCIScoconut_img/photo_2022-10-21_14-52-32.jpg)

Phân tích hàm `coconut_61`, nó đang lấy Frame dựa trên stackTrace để lấy tên hàm con thuộc `coconut_61`,trong trường hợp này là hàm `coconut_61` và `coconut_63`. Cho nên mới có kết quả khi return cái key trên. Tuy nhiên, key đó không đúng vì lúc nãy mình đã chạy thử file patched trước đó.

```c#
public static string coconut_61()
{
	StackTrace stackTrace = new StackTrace();
	return stackTrace.GetFrame(2).GetMethod().ToString() + stackTrace.GetFrame(1).GetMethod().ToString();
}
```

**Vậy vấn đề ở đây là gì ?**

Quay trở lại hàm `coconut_36`, try-catch sẽ thực hiện nhảy vào hàm `coconut_63`, nếu như hàm đó không bị lỗi và ngược lại nó sẽ nhảy vào hàm `coconut_25`. Vấn đề là khi trace tới `coconut_63` nó không bị lỗi bởi vì mình đã deobfuscate hàm đó rồi. Đó chính là mấu chốt của bài toán trên, vì vậy mình buộc phải trace vào hàm `coconut_25` thì mới return về key đúng.

**Giải pháp:**Chuyển số 3022 ra dạng hexadecimal ta được `0x0bce`, tức là `206 và 11`. Đồng thời mở file Coconut.exe ban đầu (chưa modified gì hết), ta lấy tất cả bytes của `water06`:

![warer06](/assets/img/ASCIScoconut_img/photo_2022-10-21_15-33-39.jpg)

Tìm số 206 và 11, mình thấy nó nằm trong mảng `water06`. Pattern đó chính là số 3022 thuộc đoạn `while (DateTime.Now.Year > 3022)`, mình có thể thay số 3022 thành số nào nhỏ hơn năm hiện tại trên máy (ở đây là năm 2022), ở đây mình sẽ dùng số `2019` tức là `227 07` dưới dạng bytearray. Sau đó patch 2 số đó vào vị trí của số `206 và 11`.

* `water06` sau khi được modified:

![warer06](/assets/img/ASCIScoconut_img/photo_2022-10-21_15-40-44.jpg)

Cuối cùng, chạy file sau khi sửa, ta đã thành công dump được file `DRAGON_WARRIOR.png`:

![warer06](/assets/img/ASCIScoconut_img/DRAGON WARRIOR.png)

Flag thứ 2: `_Prrrres3nt!!!!}`

Ghép lại flag1 và flag2, ta được 1 flag hoàn chỉnh: `ASCIS{7hat's_Why_7h3y_call_it_Prrrres3nt!!!!}`
Full script solve mình để ở đây: [solve](https://github.com/MrEn1gma/Writeups/blob/main/ASCIS/2022/Coconut/solve.py)
## END
Hết rồi =)))
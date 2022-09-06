---
title: Crack Me If You Can
date: 2022-09-06 12:00:00 +0700
categories: [CTF, RE]
tags: [selfmodify, idapython]     
---
# Preface

This crackme I got from https://forum.tuts4you.com/topic/37666-crackme-find-the-flag-by-extremecoders/. Although this chall is a bit old (since 2015), It still helped me to improve my IDAPython's skill.

## Introduction

* **Given files:**![findtheflag.exe](/assets/files/attachment/findtheflag.exe)
* **Description:**:You need to find the flag which will print the good boy message, Everything is allowed.
* **Category:**:Reversing
* **Summary:**:This challenge is used *Self Modify* technique, it encrypted each blocks to protect this code. Using IDAPython scripts to modify these bytecodes and save it to new file.

## Analyzing the binary

Analyze `main` function, we see that instruction has encrypted by using XOR to encrypt.

![main](/assets/img/findtheflag_img/before_dec_main.png)

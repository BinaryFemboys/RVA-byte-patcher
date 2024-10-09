# **Credits**

This tool was made by the BinFbs (od8m-deltrix).

# **Binary Femboys Bytepatch DLL**

This repository provides a typical bytepatch DLL with an integrated keyauth check_section_integrity bypass using signature scanning. This allows us to patch a running program without using x64dbg's .1337 or runtime patches.

## **Format Details**

### **Test 1**
```
0x00007FF6C85403FC | NOP
0x00007FF6C85403FE | NOP
```
---
### **Test 2**
```
0x00007FF75104117D | JNE2JE
0x00007FF751041183 | JNE2JE
```
---

## **Usage**

1. **Download the DLL:**
   - Clone or download the repository to obtain the DLL file.

2. **Apply the Patch:**
   - Use the format given to paste address no op-code needed to apply the patches to your target program.

3. **Bypass keyauth check_section_integrity:**
   - The integrated bypass will handle keyauth checks by using signature scanning.

## **References**

The pastebin used for reference: [Pastebin Link](https://pastebin.com/HL74d9BC)

## **License**

Feel free to use and modify this tool as you like as long as you dont sell it or a different copy based on this source code.

--- 



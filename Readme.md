Help message:  
```
ELF Symbol Rename Utility - ver. 1.0.20

  usage: symrename elf-binary cur-name=new-name,...

```
Example:  
```
./bin/symrename test-binary.elf funcA=funcB,count=start,abc=def
```
Verify result:  
```
nm -gD test-binary.elf
```
Note: both old and new symbols must be exact length.  

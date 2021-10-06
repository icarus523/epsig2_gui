# epsig2_gui

## Python script to generate hashes

Ported from R## L######'s LUA script version to python.  

Excerpt from epsig-readme.doc:  

### BNK File Format (*.bnk)

A BNK file is an ASCII text file.  It provides a method to combine multiple .bin files into one overall binary image.  This can saves disk space for EGMs which have a core program, base, shell or kernel.

The format of a bnk file is as follows:-

    filename1 alg1 sorp1  
    filename2 alg2 sorp2  
    ...etc  

Fields are space separated.

Where:-

- filenameX	
    The filename+ext of a binary image (max 250 chars and must not contain spaces)  
- algX		
  The hash algorithm designation type to be used for the image.  
    Refer to previous list of supported algorithm types & designations.  
    Cannot be “BLNK” (i.e. no recursion)  
    Must be upper case but don't include the quotes  
- sorp
   This field must be present and must always be equal to "p"  
   Don't include the quotes.  

### Examples of BNK files

    Konami (QCOM) MOBQ8D14.bnk (2 lines) =  
    Q13prog.bin PS32 p  
    MOBQ8D14.bin PS32 p  

    IGT (QCOM OA4) sc0130b1.bnk (2 lines) =  
    oa40227a.bin OA4R p  
    sc0130b1.bin OA4F p  


 ### v1.5
 - separate epsig2 class (for use with: from epsig2_gui import epsig2)
 - separate Cache File as a separate class
 - By Default, a File Cache is now used as the OS can manage the resource being used
 - new Seed class, to add support to formatting and different behaviours when using different hash types
 - seed is automatically padded/truncated automatically based on Hash-Type selected
 - Add support to BIN hashing (SG Gaming's ArgOS)
 - Add support to paste a complete path in the BNK/BIN file text edit field (for Bang's processes)
 - Now includes unit tests, to excercise the functions being utilised
 - Output to Output Field, has been changed to the format: <SEED>/t<HASH>/t<FNAME> - 
 - GUI has been standardised: padding, relief, etc.


### v2.0
- uses epsig.exe as main engine.
- the script is now just a wrapper
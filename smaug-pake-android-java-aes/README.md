# Smaug PAKE AES Android Java
SMAUG is an efficient post-quantum key encapsulation mechanism (KEM), whose security is based on the hardness of the lattice problems, Module-Learning-with-Errors (MLWE) and Module-Learning-with-Roundings (MLWR). SMAUG enjoys a conservative secret key security relying on the MLWE problem and an efficient ephemeral key generation relying its security on the MLWR problem. SMAUG follows the recent approaches in designing the post-quantum-secure KEMs in the Quantum Random Oracle Model (QROM) while maintaining its efficiency [ [see details](https://kpqc.cryptolab.co.kr/smaug "see details") ].
## Result
| Security Level | Metrics | a0       | b0      | a1       | b1       | TC        | TS       |
|----------------|---------|----------|---------|----------|----------|-----------|----------|
| 128            | RT      | 640,772  | 611,31  | 491,996  | 76,133   | 1132,768  | 687,443  |
|                | MU      | 58,2     | 47,2    | 57,4     | 3,5      | 115,6     | 50,7     |
|                | CPU     | 8%       | 6%      | 8%       | 2%       | 16%       | 8%       |
| 192            | RT      | 826,574  | 766,036 | 710,122  | 105,035  | 1536,696  | 871,071  |
|                | MU      | 93,1     | 81,5    | 96,5     | 4,9      | 189,6     | 86,4     |
|                | CPU     | 9%       | 8%      | 10%      | 3%       | 19%       | 11%      |
| 256            | RT      | 1111,587 | 1100,146| 1115,541 | 146,240  | 2227,128  | 1246,386 |
|                | MU      | 185,1    | 174,5   | 198,3    | 7,2      | 383,4     | 181,7    |
|                | CPU     | 12%      | 10%     | 13%      | 4%       | 25%       | 14%      |


## Further Information
More details about SMAUG and the most secure ways to use it can be found [here](https://kpqc.cryptolab.co.kr/smaug "here")

## DISCLAIMER
The tests from the C reference implementation  ([SMAUG KEM Github](https://github.com/hmchoe0528/SMAUG_public "SMAUG KEM Github")) have been converted to Java. The original test files are used as the main test source. To convert the codes, first the randomly assigned values were assigned as fixed values in the C application. Thus, the same keys were generated in both applications (C and Java). The tests all pass, however please note that the code has not been examined by a third party for potential vulnerabilities.

## Contact
faruk.dursun@bil.omu.edu.tr

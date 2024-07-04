# Smaug KEM Android Java
SMAUG is an efficient post-quantum key encapsulation mechanism (KEM), whose security is based on the hardness of the lattice problems, Module-Learning-with-Errors (MLWE) and Module-Learning-with-Roundings (MLWR). SMAUG enjoys a conservative secret key security relying on the MLWE problem and an efficient ephemeral key generation relying its security on the MLWR problem. SMAUG follows the recent approaches in designing the post-quantum-secure KEMs in the Quantum Random Oracle Model (QROM) while maintaining its efficiency [ [see details](https://kpqc.cryptolab.co.kr/smaug "see details") ].
## Setup
**Step 1.** Add the JitPack repository to your build file
```
dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
  }
}
```

**Step 2.** Add the dependency
```
dependencies {
  implementation 'com.github.afDursun:smaug-kem-android-java:1.0.2'
}
```
## Example Use
```java
SmaugKEM smaug = new SmaugKEM(new Smaug_128()); //new Smaug_128(), new Smaug_192(), new Smaug_256()

Key key = smaug.keygen(); //key.getPk() & key.getSk()

Encapsulation enc  = smaug.encapsulation(key.getPk()); //enc.getCt  & enc.getSsk();

byte[] ssk = smaug.decapsulation(key.getSk() , key.getPk() , enc.getCt());
```

If you want to make random values constant
```java
SmaugKEM smaug = new SmaugKEM(new Smaug_128()); 
smaug.random_generate(true); //default false
```

## Further Information
More details about SMAUG and the most secure ways to use it can be found [here](https://kpqc.cryptolab.co.kr/smaug "here")

## DISCLAIMER
The tests from the C reference implementation  ([SMAUG KEM Github](https://github.com/hmchoe0528/SMAUG_public "SMAUG KEM Github")) have been converted to Java. The original test files are used as the main test source. To convert the codes, first the randomly assigned values were assigned as fixed values in the C application. Thus, the same keys were generated in both applications (C and Java). The tests all pass, however please note that the code has not been examined by a third party for potential vulnerabilities.

## Contact
ahmetfarukdursun@ktu.edu.tr

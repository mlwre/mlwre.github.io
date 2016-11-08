---
title: Automating Jsocket Config Extraction
updated: 2016-11-08 00:00
---
# Automating Jsocket Config Extraction
In this post we will show you how to basically solve common issues when trying to unpack or extract configurations from the Jsocket malware family.
Although the specific information presented below is specific to Jsocket, you can use the tools and techniques with other Java Malware.

First, we are going to talk about Jsocket and why we chose this family as an example.

Why Java you ask?

- Because it's enterprise ready!
- Because 4 billion devices can't be wrong!
- Because you can run python inside Java! and Ruby! and C! and Pascal! and Perl! and PHP! and Visual Basic! WAIT WHAT?!
- Write once, pwn anywhere!

<p align="center">
  <img src="https://memecrunch.com/meme/BJFWH/java/image.gif" alt="Like a sir!"/>
</p>

Of course, Jsocket is a Java Malware (heh J-something, get it?), more specifically a **R**emote **A**dministration **T**ool and it is... a multiplatform one.

Its capabilities:

- Keylogger
- Remote Desktop Connection
- Mic Capture
- Webcam Capture
- Execute remote files
- etc...

One kinda misses novel Netbus functionality like popping the CD drive tray open. Alas, I digress.

It seems that Jsocket is a cool, fancy RAT. But where does it come from? What came first, the JVM or the byte code? Why did the JVM cross the road? Oh, boy, I could go on for hours!

## History of Jsocket

Roughly, the Jsocket familiy tree looks something like this:
Frutas RAT >> ADWIND >> UNRECOM >> ALIENSPY >> JSOCKET

We would like to apologize in advance for the atrocious Spanish in the screencaps below.  

- Frutas RAT is the first known version of what would later become the Jsocket malware. It was developed by "Adwind" a user in a  Spanish forum called "indetectables" (undetectable):

   In the picture below he breaks it to the world that he has a new project called Frutas RAT and that he is developing it alone without reusing code from other projects:

  ![](https://i.imgur.com/uFpKtz2.png)
  
  There is always a first time:
  
  ![](https://i.imgur.com/tmg5DQx.png)

   Frutas is, at some point, used in targeted attacks as well. Critical success!
   https://www.symantec.com/connect/blogs/targeted-attacks-delivering-fruit

- In a surprising development, the project gets renamed to... Adwind. Pressumably Adwin himself continues to develop the project.
  He comes up with a business model in order to reap the benefits of his hard work:

  ![](https://i.imgur.com/OqmCmfN.png)
  
  Advertised as A cheap trojan which anyone can buy to control remotely computers! This second version gets a bit of a facelift and maturity feature wise, looking like this:
  
  ![](https://i.imgur.com/wMS0CF1.png)

- After that, a new player comes to town: Unrecom. Adwind is later on discontinued as an (alleged) exit strategy, Adwind (allegedly)  sold the project to another guy called "faria". He also gave some licenses for free to the registered users in indetectables forum, because first one is for free, you know?:
  
  ![](https://i.imgur.com/Ysx1isd.png)
  
  ![](https://i.imgur.com/zeDzheO.png)

  The malware gets some love and a bit of a facelift:
  
  ![](https://i.imgur.com/BPgkn2s.png)

  The developer calls himself "Supporter 747" 

- Just after that, a different product called breaks into the market, apparently continued by different people. The following picture also explain that they are a group of java "developers": "Support747, unrecom, OberonSofware and Alien781 or AlienSpy".
  But basically, they were one by one booted from the project:
  - Support747 starts to cheat customers.
  - OberonSoftware does the same, but also published the source code.
  - Unrecom basically slacked and delayed the project.
  
  So at that momment only Alien781 is working on the project helped (according the picture) by SquilaMax and Pedro18. 

  ![](https://i.imgur.com/kBozMoU.png)

  The interface gets some more work:
  
  ![](https://i.imgur.com/B17I4a7.png)

- Finally, Jsocket, our analysis target, is definifely more mature that previous attempts, which appears to be the latest and greatest from the AlienSpy group:
  
  ![](https://i.imgur.com/qE90QJQ.png)

## Why would you need yet another tool to decrypt configs? 

In most cases Java is really easy to analyze since you can use pretty much any decompiler and get the java code, read it and understand it completely. In most cases... other times not so much, you find java that is completely obfuscated, and that makes it harder to understand the code and ultimately unpack or extract the config.

Also, sometimes existing tools (big shout out to malwareconfig.com) don't give you exactly what you need and you have to get creative.

Or you just want to learn a new trick.

So, with our researcher hat on, we dug until we came across something cool on the interwebs: "Java Agents". 'tis like PIN but for instrumenting inside Java. Follow?

Java Agents are usually used in profiling Java apps so it is a tool mostly used by Jdevs, but for some reason they are not commonly used in security. 

So, to give you an example, there are known profiling tools that are agent based, for example: https://www.overops.com/

When it comes down to agents, there are 2 major types:

- Java Agents
- Native Agents

We will use native agents since they seem to fit our purpose better.

Now, some high level steps to make it work:

1. Download your favorite compiler/editor (I use visual studio c++)
2. Paste the code below and do any changes you deem necessary. Don't like our options? add your own!
3. Compile. You will get a dll, place in C:\Windows\System32 to make things simple
4. Run java with with a Java Agent.

It's important to note that when you run a java file you can specify a java agent to use. 
In our case we are going to choose the dll we just compiled:

```
  java -agentlib:{our dll} -jar {our sample}
  java -agentlib:tracer -jar jsocket.jar
```

## But HOW does it work?

Well, we are going to trace specific API calls from the Java Virtual Machine. If you are familiar with instrumentation techniques and tools as frida, PIN, etc, those are also different ways to do it, nothing wrong with them.

So, to state our purpose: we are basically instrumenting java code with the goal of getting the configuration or wherever we want in clear text.

**Disclaimer:** You know, the usual disclaimer about not reinventing the wheel, this is Frankencode from different places, do not look at it too long, it gives eye cancer, introduces vulnerabilities, has not been tested on animals, etc. Which reminds me, I would like offer a goat in sacrifice to the original nameless authors of the bits and pieces of the frankencode below. 

First we need to include some libs:

```c++
#include "jvmti.h"
#include "jni.h"
#include <string>
#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
#include <ctime>
#include "windows.h"
using namespace std;
```

Then when the agent is loaded in the JVM it will cal this function:
```c++
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
```
That function receives an instance of the vm and the options passed to it, which we can work with later on:
```c++
{
  option = options;
  jvmtiEnv *jvmti;
  jvmtiCapabilities cap = { 0 };
  jvmtiEventCallbacks callback = { 0 };

  if (option == "help") {
    printf("This is a Help for the Tracer Agent \n");
    printf("------------------------------------ \n");
    printf("Is pretty easy to use, just some options\n");
    printf("help --> This Help\n");
    printf("manual --> Manual extracting, need also a method to get example: manual,method='jJsJjJsjJJJjJjJjsJjjsJjsJjjsjjJjJIiiIIIiIII',signature='()[B'\n");
    printf("auto --> Just take a sit and wait till all the bytearray are dumped(can have FP)");
    exit(0);
  }
  else if (option == "manual") {
    printf("Welcome to the manual part \n");
    printf("Please give me the method\n");
    std::cin >> meth;
    printf("Please give me the signature\n");
    std::cin >> sign;
  }
  else if (option == "auto") {
    printf("Take a sit and wait until all dumps were done\n");
  }
  else
  {
    printf("Bye Bye...");
    exit(0);
  }
  // Get the jvmti environment pointer
  jint version = vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_2);
  // We need callbacks for method exit events
  cap.can_generate_method_exit_events = 1;
  // Add the capability
  jvmti->AddCapabilities(&cap);
  // Register callback
  callback.MethodExit = &MethodExitCallback;
  jvmti->SetEventCallbacks(&callback, sizeof(jvmtiEventCallbacks));
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
  return JVMTI_ERROR_NONE;
}
```

Then it will wait for different callbacks and execute specific code when the events occur:
```c++
void JNICALL MethodExitCallback(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value)
```

Tool gives you 3 options:

- Help (always good to have some help...)
- Manual (the tool will ask the user which method to intercept)
- Auto (the tool will instrument all the methods that return a ByteArray in order to try to get the config)


### Manual Process

Since the help and the auto mode is trivial to explain, we are going to explain the meat of the tool with the manual process as an example:

Things you're going to need:

- [ByteCodeViewer](https://bytecodeviewer.com/)
- Jsocket sample (We will work with this one: `5632961e750de4c1398a830df3cb4416`)
- Our code compiled as a dll

First, load into the bytecodeviewer the jar of malware. If its encoded you will see something similar to this:

![](https://i.imgur.com/gQHfu6i.png)

For experience, the interesting functions are normally functions that return ByteArrays. So typically if you are trying to get the deofuscated code this is what you would go for, but you can also intercept  the functions that return strings if you want. (You probably need to modify the code a little, but it's not rocket surgery...)

One thing that you need to take in account when you deal with Java ofuscated code or poliformism is the method signatures. In Java you can have lots of methods with the same name but different parameters or return types. Java differentiates them by what is called a method signature, roughly a function of the method name and number and type of its parameters.

So, you need to tell the program which specific one you want intercept.

Bytecodeviewer is an awesome tool to do this. In the ByteArray panel you can see that easily. So the goal was to intercept functions that return bytearray, and seems interesting beacuse their parameters are 2 string, 2 byte array or wherever you think. 

You can also intercept all, shotgun approach, and hopefuly you can get your decoded config if you haven't fat-fingered stuff.

![](https://i.imgur.com/uPOGDdG.png)

Then you need to compile the dll if you haven't. **Note:** If you just paste the code into VisualStudio you will get a bunch of errors since you need to include the java headers from VC++

![](https://i.imgur.com/vquxOOK.png)

After some tries we discover our method in this case and signature, which in this case is:

- Method: XXXXXXXXXXXXXXXXxxxXXXXXa
- Signature: `([B)[B`

**Note**: Remember that you are playing with real malware, don't infect yourself ;)

Then, run our tool...

![](https://i.imgur.com/tfOmvNx.png)

A file will be written in the same folder where you launched the Java App:

![](https://i.imgur.com/T5n92cv.png)

Load it in the bytecode viewer, you will be able to read the code easily, and of course the complete config in clear text:

![](https://i.imgur.com/O9sEwPB.png)

Note: The manual part works really well, Auto mode probably needs some modifications for better performance.

### Final working code

```c++
#include "jvmti.h"
#include "jni.h"
#include <string>
#include <iostream>
#include <ctime>
#include <fstream>
#include <sstream>
#include <ctime>
#include "windows.h"
using namespace std;

string option = "";
string meth = "";
string sign = "";

void JNICALL MethodExitCallback(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value)
{
  char *name, *signature;
  bool quit = false;
  if (option == "manual")
  {
    if (JVMTI_ERROR_NONE == jvmti_env->GetMethodName(method, &name, &signature, NULL))
    {
      string nam = name;
      string sig = signature;
      if ((nam == meth) && (sig == sign) && was_popped_by_exception == JNI_FALSE)
      {
        string token, mystring(sig);
        string returned;
        while (token != mystring) {
          token = mystring.substr(0, mystring.find_first_of(")"));
          mystring = mystring.substr(mystring.find_first_of(")") + 1);
          returned = token;
        }
        if ((returned == "Ljava/lang/String;") && (was_popped_by_exception == JNI_FALSE))//String returned
        {
          FILE *outf;
          jstring streturn = (jstring)return_value.l;
          if (streturn != NULL)
          {
            const char *nativestr = jni_env->GetStringUTFChars(streturn, JNI_FALSE);
            if (nativestr != nullptr)
            {
              errno_t errorCode = fopen_s(&outf, "strings.txt", "a");
              fprintf(outf, "%s\n", nativestr);
              fclose(outf);
            }
          }
        }
        if (returned == "[B") //ByteArray returned
        {
          FILE *outf;
          jbyteArray byteArr = (jbyteArray)return_value.l;
          jint arraySize = jni_env->GetArrayLength(byteArr);
          jbyte *elem = jni_env->GetByteArrayElements(byteArr, NULL);
          SYSTEMTIME st;
          GetSystemTime(&st);
          char currentTime[84] = "";
          sprintf_s(currentTime, "%d-%d-%d-%d-%d-%d-%d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
          string buf = currentTime;
          string t = "decrypted_" + buf + ".zip";
          errno_t errorCode = fopen_s(&outf,t.c_str(), "wb");
          fwrite(elem, arraySize, 1, outf);
          fclose(outf);
          jni_env->ReleaseByteArrayElements(byteArr, elem, JNI_ABORT); // Free memory
        }
      }
      jvmti_env->Deallocate((unsigned char*)name);
      jvmti_env->Deallocate((unsigned char*)signature);
    }
  }
  if (option == "auto")
  {
    if (JVMTI_ERROR_NONE == jvmti_env->GetMethodName(method, &name, &signature, NULL))
    {
      string nam = name;
      string sig = signature;
      string token, mystring(sig);
      string returned;
      while (token != mystring) {
        token = mystring.substr(0, mystring.find_first_of(")"));
        mystring = mystring.substr(mystring.find_first_of(")") + 1);
        returned = token;
      }
      if ((returned == "Ljava/lang/String;") && (was_popped_by_exception == JNI_FALSE))//String returned
      {
        FILE *outf;
        jstring streturn = (jstring)return_value.l;
        if (streturn != NULL)
        {
          const char *nativestr = jni_env->GetStringUTFChars(streturn, JNI_FALSE);
          if (nativestr != nullptr)
          {
            errno_t errorCode = fopen_s(&outf, "strings.txt", "a");
            fprintf(outf, "%s\n",nativestr);
            fclose(outf);
          }
        }
      }
      if ((returned == "[B") && (was_popped_by_exception == JNI_FALSE)) //ByteArray returned
      {
        FILE *outf;
        jbyteArray byteArr = (jbyteArray)return_value.l;
        if (byteArr != NULL)
        {
          jint arraySize = jni_env->GetArrayLength(byteArr);
          jbyte *elem = jni_env->GetByteArrayElements(byteArr, NULL);
          SYSTEMTIME st;
          GetSystemTime(&st);
          char currentTime[84] = "";
          sprintf_s(currentTime, "%d-%d-%d-%d-%d-%d-%d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
          string buf = currentTime;
          string t = "decrypted_" + buf + ".zip";
          if (elem != nullptr)
          {
            if (arraySize > 9000 && arraySize != 0) 
            {
              string hea(reinterpret_cast<char*>(elem), 2);
              if (hea == "PK" )
              {
                errno_t errorCode = fopen_s(&outf, t.c_str(), "wb");
                fwrite(elem, arraySize, 1, outf);
                fclose(outf);
                jni_env->ReleaseByteArrayElements(byteArr, elem, JNI_ABORT); // Free memory
              }           
            }
          }
        }
      }
    }
  }
}

/*
Called when agent is loaded for first time
*/
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
  option = options;
  jvmtiEnv *jvmti;
  jvmtiCapabilities cap = { 0 };
  jvmtiEventCallbacks callback = { 0 };

  if (option == "help") {
    printf("This is a Help for the Tracer Agent \n");
    printf("------------------------------------ \n");
    printf("Is pretty easy to use, just some options\n");
    printf("help --> This Help\n");
    printf("manual --> Manual extracting, need also a method to get example: manual,method='jJsJjJsjJJJjJjJjsJjjsJjsJjjsjjJjJIiiIIIiIII',signature='()[B'\n");
    printf("auto --> Just take a sit and wait till all the bytearray are dumped(can have FP)");
    exit(0);
  }
  else if (option == "manual") {
    printf("Welcome to the manual part \n");
    printf("Please give me the method\n");
    std::cin >> meth;
    printf("Please give me the signature\n");
    std::cin >> sign;
  }
  else if (option == "auto") {
    printf("Take a sit and wait until all dumps were done\n");
  }
  else
  {
    printf("Bye Bye...");
    exit(0);
  }
  // Get the jvmti environment pointer
  jint version = vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_2);
  // We need callbacks for method exit events
  cap.can_generate_method_exit_events = 1;
  // Add the capability
  jvmti->AddCapabilities(&cap);
  // Register callback
  callback.MethodExit = &MethodExitCallback;
  jvmti->SetEventCallbacks(&callback, sizeof(jvmtiEventCallbacks));
  jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
  return JVMTI_ERROR_NONE;
}
```


See you on the next analysis! 

The Malware Hunter!

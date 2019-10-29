## Vulnerable RESTful Web App with Node.js, Express, and MongoDB

final project by *Xue Zou*, <br>
Course Cyber-security from Vanderbilt University, <br>
fall 2019, taught by *Dr.Christopher Jules White* 

### Goal
Design a web app with Node.js, Express, and MongoDB and RESTful APIs and demonstrate the **OSWAP Top Ten** on it.

#### Table of Contents

- [OWASP Top 10](#owasp-top-10)
- [About the Web App](#about-the-web-app)
- [Vulnerabilities of the Web App](#vulnerabilities-of-the-web-app)
- [Run](#run)
- [Progress Outline](#progress-outline--answer-to-heilmeier-questions)
- [Clickjacking Vulnerability on YES](#an-interesting-clickjacking-vulnerability-on-vanderbilt-system-yes)

### OWASP Top 10

##### Current official release [OWASP Top 10 2017](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)

##### what is [OWASP](www.owasp.org)?

The Open Web Application Security Project, or OWASP, is a open non-profit community dedicated to improving the security of software. Their mission is to make software security visible, such that individuals and organizations are able to make informed decisions. 

One of OWASP's core principle is free and open, as all of the OWASP tools, documents, forums, and chapters are free and open to anyone interested in improving application security. One of their best-known project is the OWASP Top 10.

##### what is [OWAWP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)?

The OWASP Top 10 is a regularly-updated report outlining security concerns for web application security, representing a broad consensus about what the 10 most critical web application security flaws are. The report is put together by a team of security professionals from all over the world. OWASP refers to the Top 10 as an ‘awareness document’ and they recommend that all companies incorporate the report into their processes in order to mitigate security risks.

Below are the security risks reported in the OWASP Top 10 2017 report:

1. **Injection**

    Injection attacks happen when malicious data is sent to an interpreter through a form input to a web application. For example, the infamous SQL Injection enter SQL command into a form that expects a plaintext.

    Typically, to prevent injection attack, developers should always think carefully about the design of interfaces of APIs and use positive or "whitelist" server-side input validation.

2. **Broken Authentication**
    
    This type of attack relates to the user's identity, authentication, and session management. Some vulnerabilitoes in authentication systems can give attackers access to user accounts and even the admin account. For example, an attacker can take lists of known words against a user to form different combinations of passwords and then brute force trying all those combinations on the login system to see if there are any that work.

    Some strategies to mitigate authentication vulnerabilities are implementing weak password check, multi-factor authentication as well as avoiding deploying default credentials and limiting or delaying repeated login attempts using rate limiting.

3. **Sensitive Data Exposure**

    Sensitive Data Exposure is related to protection of sensitive data such as passwords, credit card numbers, health records, personal information and business secrets etc. Attackers can gain access to that data and sell or utilize it for bad purposes.

    Data exposure risk can be mitigated by encrypting all sensitive data with strong algorithms, as well as disabling the caching of any sensitive information. Additionally, developers should ensure that they are not unnecessarily storing any sensitive data.

4. **XML External Entities (XXE)**
    
    This attack relates a XML-based web application. This input can reference an external entity, attempting to exploit a vulnerability in the parser. An ‘external entity’ in this context refers to a storage unit, such as a hard drive. An XML parser can be duped into sending data to an unauthorized external entity, which can pass sensitive data directly to an attacker.

    To mitigate XEE attacks, the easiest way is to use less complex data formats such as JSON, and avoiding serialization of sensitive data, or at the very least to patch XML parsers and disable the use of external entities in an XML application.

5. **Broken Access Control**

6. **Security Misconfiguration**

7. **Cross-Site Scripting (XSS)**

8. **Insecure Deserialization**

9. **Using Components with known Vulnerabilities**

10. **Insufficient Logging & Monitoring**



### About the Web App

The app is developed with and NonSQL database MongoDB

The contents are
* /public - static directories suchs as /images
* /routes - route files
* /views - views
* README.md - this file
* app.js - central app file 
* package.json - package info



### Vulnerabilities of the Web App

Here I would list how to exploit these vulnerabilities on the application and also propose some solutions.

1. **Injection**

Here


2. **Broken Authentication**

The admin interface is accessible by anyone.

3. **Sensitive Data Exposure**

The password is stored as plaintext in database

4. **XML External Entities (XXE)**
5. **Broken Access Control**
6. **Security Misconfiguration**
7. **Cross-Site Scripting (XSS)**
8. **Insecure Deserialization**
9. **Using Components with known Vulnerabilities**

Here

10. **Insufficient Logging & Monitoring**


1. Out of date dependencies

npm audit 
did a great job to 

A simple command `npm audit fix` would be able to fix them.


**4. injection attack**
https://www.owasp.org/index.php/Testing_for_NoSQL_injection
Testing for NoSQL injection from OWASP

https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html

because of express parser (or body parser)

do
```javascript 
await fetch("http://localhost:3000/users/session", {"credentials":"include","headers":{"accept":"application/json, text/javascript, */*; q=0.01","accept-language":"en,zh-CN;q=0.9,zh;q=0.8","cache-control":"no-cache","content-type":"application/x-www-form-urlencoded; charset=UTF-8","pragma":"no-cache","sec-fetch-mode":"cors","sec-fetch-site":"same-origin","x-requested-with":"XMLHttpRequest"},"referrer":"http://localhost:3000/","referrerPolicy":"no-referrer-when-downgrade","body":"username[$gt]=&password[$gt]=","method":"POST","mode":"cors"});
```

POST /users/session

after  
req.body becomes 
{ username: '{"$gt": ""}', password: '{"$gt": ""}' }

For this particular attack example, design problem
should not check password like such. 
should first find the user with one username and 
...

To protects against Dollar $ injection attacks for 

checks req.params, req.body and req.query for objects and recursively scans for the $ symbol as the first property key and responds with an error if it is detected.

 coders forget to right validators for route and this can be a huge security issue.


in the console

How to avoid


### Run

To connect to local mongoDB, for example, I have `mongod --dbpath ~/Documents/mongo/db`.

To run the code, git clone and first run `npm install` to install all all required dependencies. Then, run `npm run live` to run the node server and go to `http://localhost:3000` for user interface and `http://localhost:3000/admin` for admin interface.

Here are some illustrations:




### Progress Outline / Answer to Heilmeier questions

There are already some vulnerable web apps written in NodeJS, such as [dvna](https://github.com/appsecco/dvna) or [vulnerable-node](https://github.com/cr0hn/vulnerable-node) or [OWASP's NodeGoat](https://github.com/OWASP/NodeGoat).

The goal of this project is different from those, as it focus on writing really vulnerable nodejs web app to play around with super simple UI interface and back-end APIs.

The vulnerable application could be used to educate, develop and test against. 

The project would take the later half of the course. To check the mid-term success, I want to finish all 10 identifications and demonstrations of the vulnerabilities. For final exam for this project, I am going to demonstrate the project in a final informative video and finish the final writeup.

### Final Video demo

Leave this for later. 


### References
1. Code starter reference from [Learn the basics of REST and use them to build an easy, fast, single-page web app.](https://github.com/cwbuecheler/node-tutorial-2-restful-app)
2. More about [OWASP top 10](https://www.cloudflare.com/learning/security/threats/owasp-top-10/)
3. [Injection attack with mongoDB and nodeJS](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)

### An interesting Clickjacking vulnerability on Vanderbilt system YES

This is not part of my final project but I want to also share my process of discovery here. Please visit *[clickjacking](./clickjacking)* if interested.

---
<!-- 
npm install
```
found 7 vulnerabilities (3 low, 1 moderate, 2 high, 1 critical)
run `npm audit fix` to fix them, or `npm audit` for details
```

npm audit

find npm audit then we could get the security report with the risk level, dependency specific details of path and a url of more info on the vulnerability.

Also it offers specific command to update and fixxes these known vulnerabilities, which is super nice.

There are 7  Denial of Service from mongodb,  Code Injection    from Morgan
                                                                                
                       === npm audit security report ===                        
                                                                                
# Run  npm install monk@7.1.1  to resolve 1 vulnerability
SEMVER WARNING: Recommended action is a potentially breaking change
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ High          │ Denial of Service                                            │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ mongodb                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ monk                                                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ monk > mongodb                                               │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/1203                            │
└───────────────┴──────────────────────────────────────────────────────────────┘
──────────────────────────────────────────────────────────────┘


# Run  npm update mongodb --depth 1  to resolve 1 vulnerability
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ High          │ Denial of Service                                            │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ mongodb                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ mongodb                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ mongodb                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/1203                            │
└───────────────┴──────────────────────────────────────────────────────────────┘


┌──────────
└──────────────────────────────────────────────────────────────────────────────┘
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ Low           │ Incorrect Handling of Non-Boolean Comparisons During         │
│               │ Minification                                                 │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ uglify-js                                                    │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Patched in    │ >= 2.4.24                                                    │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ jade                                                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ jade > transformers > uglify-js                              │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/39                              │
└───────────────┴──────────────────────────────────────────────────────────────┘
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ Low           │ Regular Expression Denial of Service                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ uglify-js                                                    │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Patched in    │ >=2.6.0                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ jade                                                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ jade > transformers > uglify-js                              │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/48                              │
└───────────────┴──────────────────────────────────────────────────────────────┘
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ Critical      │ Sandbox Bypass Leading to Arbitrary Code Execution           │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ constantinople                                               │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Patched in    │ >=3.1.1                                                      │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ jade                                                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ jade > constantinople                                        │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/568                             │
└───────────────┴──────────────────────────────────────────────────────────────┘
┌───────────────┬──────────────────────────────────────────────────────────────┐
│ Low           │ Regular Expression Denial of Service                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Package       │ clean-css                                                    │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Patched in    │ >=4.1.11                                                     │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Dependency of │ jade                                                         │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ Path          │ jade > clean-css                                             │
├───────────────┼──────────────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/785                             │
└───────────────┴──────────────────────────────────────────────────────────────┘
There are  `npm audit fix` to fix 2 of them.

  1 vulnerability requires semver-major dependency updates.
  4 vulnerabilities require manual review. See the full report for details.

 -->
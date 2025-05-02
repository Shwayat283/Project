How to format the code snippets in Microsoft Word
 
https://www.youtube.com/watch?v=busnzKKSOxU
 youtube.com/watch?v=ZQz_H_IV1aE


____

- [ ] take my document from GitHub 


- [ ] take these file and put them in the main documentation file
___
files architecture
**4.1.3.1** Core Scanning Architecture  
**4.1.3.2** Workflow Phases
**4.1.3.3** Payload Generation Strategy
**4.1.3.4** Detection Heuristics
**4.1.3.5** Exploitation Subsystem
**4.1.3.6** Concurrency Model
**4.1.3.7** Error & Edge Case Handling
____

maybe the final result be like this:
### **4.1.3 How the Path Traversal Scanner Works**

**4.1.3.1** Core Scanning Architecture  
_(Class structure, initialization process, component relationships)_

**4.1.3.2** Workflow Phases

1. Target Discovery & Crawling
2. Parameter Analysis 
3. Payload Injection 
4. Vulnerability Validation 
5. Conditional Exploitation 

**4.1.3.3** Payload Generation Strategy

- Encoding techniques (double-URL, null-byte, etc.) 
- OS-specific patterns (Linux/Windows) 
- Custom payload integration 

**4.1.3.4** Detection Heuristics

- HTTP status code analysis 
- Content pattern matching (e.g., `/etc/passwd` signatures) 
- Response length anomalies 
- False positive reduction 

**4.1.3.5** Exploitation Subsystem

- Post-detection file read attempts 
- Log-based RCE detection 
- User-specific file generation 

**4.1.3.6** Concurrency Model

- Thread pool implementation 
- Resource management 
- URL deduplication 

**4.1.3.7** Error & Edge Case Handling

- Network failure recovery 
- Encoding normalization 
- Session/cookie persistence

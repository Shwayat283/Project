

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a1a', 'edgeLabelBackground':'#333'}}}%%
flowchart TD
    A([Start]) --> B[Initialize Scanner]
    B --> C[Parse CLI Arguments]
    C --> D[Configure Proxy]
    D --> E{Enable Crawling?}
    E -->|Yes| F[Start Site Crawler]
    E -->|No| G[Use Provided Parameters]
    F --> H[Discover Parameters]
    G --> I[Prepare Detection]
    H --> I
    I --> J[Error-Based Detection]
    J --> K{Found Engine?}
    K -->|Yes| L[Log Vulnerability]
    K -->|No| M[Evaluation-Based Detection]
    M --> N{Found Engine?}
    N -->|Yes| L
    N -->|No| O[No Vulnerability Found]
    L --> P[Generate Report]
    O --> P
    P --> Q{Start Interactive Shell?}
    Q -->|Yes| R[Initialize Exploiter]
    R --> S[Interactive Command Execution]
    S --> T[Execute Commands/Read Files]
    T --> U{Exit?}
    U -->|Yes| V([End])
    U -->|No| T
    Q -->|No| V
    style A fill:#4CAF50
    style V fill:#F44336
    style L fill:#2196F3
    style O fill:#9E9E9E
    style S fill:#FF9800

```




Key components mapped to your code:

1. **Site Crawler**: Handled by `SiteCrawler` class with BFS crawling
    
2. **Detection Methods**:
    
    - Error-based (`ErrorBasedEngineDetector`)
        
    - Evaluation-based (`EvaluationBasedEngineDetector`)
        
3. **Exploitation**:
    
    - `SSTIExploiter` class handling command execution/file reading
        
    - `interactive_shell` function for user interaction
        
4. **Reporting**:
    
    - JSON/CSV report generation in `generate_report`
        
5. **CLI Flow**:
    
    - Argument parsing and configuration
        
    - Proxy setup and verbosity control
        

Visual Features:

1. Color-coded nodes for different phases
    
2. Clear decision points (diamonds)
    
3. Parallel detection workflows
    
4. Interactive exploitation loop
    
5. Error handling paths
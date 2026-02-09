# Contributing to Zetton

## About the Team

**Zetton** was developed by the **UTSA Cyber Jedis Quantum Cybersecurity Team**, a group of cybersecurity researchers exploring the intersection of quantum computing and digital forensics.

We're passionate about pushing the boundaries of security research and making quantum-assisted analysis accessible to the broader security community.

---

## We Need Your Help!

Whether you're a fellow Jedi, a UTSA student, or a security researcher from anywhere in the galaxy, we'd love your contributions! This project combines cutting-edge quantum computing with traditional binary analysis, and there's plenty of room for innovation.

### Who Can Contribute?

- **UTSA Students**: Join us in advancing quantum cybersecurity research
- **Cyber Jedis**: Share your security expertise and help expand Zetton's capabilities
- **Quantum Computing Enthusiasts**: Help optimize our quantum algorithms
- **Security Researchers**: Contribute new analysis techniques and detection patterns
- **Everyone Else**: Documentation, testing, bug reports - all contributions are valuable!

---

## Current Project Status

Zetton is in **active alpha development**. Here's what we have so far:

### What's Working
- Complete package structure with proper Python packaging
- Functional CLI with Click and Rich formatting
- Virtual environment setup for Kali Linux/Debian systems
- Configuration management framework
- Module organization (analyzers, core, crypto, forensics, loaders, quantum, utils)

### What's In Progress
- Binary format loading (ELF, PE, Mach-O)
- Quantum engine implementation
- Cryptographic pattern detection
- Analysis module implementations

### What's Needed
- Implementation of core analysis features
- Quantum algorithm development
- Testing infrastructure
- Documentation improvements
- Integration with existing security tools

**Your contributions can directly shape this project!** Early contributors have the opportunity to influence architecture and design decisions.

---

## Ways to Contribute

### Bug Reports
Found something that doesn't work? Let us know! Include:
- Your environment (OS, Python version, Qiskit version)
- Steps to reproduce the issue
- Expected vs. actual behavior
- Any relevant error messages
- Screenshots if applicable

### Feature Requests
Have ideas for new quantum algorithms or analysis techniques? We want to hear them!
- Describe the feature and its use case
- Explain how it would benefit security research
- Share any relevant research papers or references
- Note if you're willing to implement it yourself

### Code Contributions
Ready to hack on Zetton? Awesome! Here's how:

1. **Fork the repository**
   ```bash
   # On GitHub, click "Fork" button
   git clone https://github.com/YOUR_USERNAME/zetton.git
   cd zetton
   ```

2. **Set up your development environment**
   ```bash
   # Create virtual environment
   python3 -m venv zetton-dev
   source zetton-dev/bin/activate
   
   # Install in development mode with all dependencies
   pip install -e ".[all]"
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-amazing-feature
   ```

4. **Make your changes**
   - Follow PEP 8 style guidelines
   - Add docstrings to new functions (Google-style)
   - Include type hints where appropriate
   - Keep the existing project structure

5. **Test your changes**
   ```bash
   # Test the CLI
   zetton --help
   zetton status
   
   # Test your specific feature
   python -c "from zetton.your_module import your_function; your_function()"
   
   # Run tests when available
   pytest tests/ -v
   ```

6. **Commit with clear messages**
   ```bash
   git add .
   git commit -m "Add quantum pattern matching for XOR encryption"
   
   # Use descriptive commit messages following this format:
   # - "Add [feature]" for new features
   # - "Fix [issue]" for bug fixes
   # - "Update [component]" for improvements
   # - "Docs: [description]" for documentation
   ```

7. **Push and create a pull request**
   ```bash
   git push origin feature/your-amazing-feature
   # Then create PR on GitHub
   ```

### Documentation
- Improve existing documentation (README, INSTALLATION.md, etc.)
- Add usage examples and tutorials
- Document new features as you implement them
- Fix typos and clarify confusing sections
- Add code comments for complex logic

### Research Contributions
- Implement new quantum algorithms for binary analysis
- Add support for additional cryptographic patterns
- Optimize existing quantum circuits
- Benchmark quantum vs. classical performance
- Write research papers or blog posts about your findings

---

## Development Setup

### Complete Setup Guide

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/zetton.git
cd zetton

# 2. Create virtual environment (REQUIRED on Kali/Debian)
python3 -m venv zetton-dev
source zetton-dev/bin/activate

# 3. Upgrade pip
pip install --upgrade pip setuptools wheel

# 4. Install Zetton with all development dependencies
pip install -e ".[all]"

# 5. Verify installation
zetton --version
zetton status

# 6. Set up git remote for upstream
git remote add upstream https://github.com/keebanvillarreal/zetton.git
```

### Keeping Your Fork Updated

```bash
# Fetch latest changes from upstream
git fetch upstream

# Merge into your main branch
git checkout main
git merge upstream/main

# Push to your fork
git push origin main
```

### Directory Structure

When contributing, understand the package structure:

```
zetton/                          # Repository root
├── pyproject.toml              # Package configuration
├── setup.py                    # Setup script
├── MANIFEST.in                 # Distribution files
├── README.md                   # Main documentation
├── CONTRIBUTING.md             # This file
├── LICENSE                     # MIT License
│
├── zetton/                     # Main Python package
│   ├── __init__.py            # Package initialization
│   ├── cli.py                 # Command-line interface
│   │
│   ├── analyzers/             # Analysis engines
│   │   └── __init__.py
│   │
│   ├── core/                  # Core framework
│   │   └── __init__.py
│   │
│   ├── crypto/                # Cryptanalysis
│   │   └── __init__.py
│   │
│   ├── forensics/             # Digital forensics
│   │   └── __init__.py
│   │
│   ├── loaders/               # Binary parsers
│   │   └── __init__.py
│   │
│   ├── quantum/               # Quantum algorithms
│   │   └── __init__.py
│   │
│   └── utils/                 # Utility functions
│       └── __init__.py
│
├── tests/                     # Test suite (to be expanded)
│   └── __init__.py
│
├── examples/                  # Example scripts
│   └── README.md
│
└── docs/                      # Additional documentation
    └── README.md
```

### Running Tests

```bash
# Currently minimal test infrastructure
# As you add features, add tests!

# Run tests (when available)
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=zetton --cov-report=html

# Check code style
black --check zetton/
flake8 zetton/

# Type checking
mypy zetton/
```

---

## Code Style Guidelines

### Python Style
- **Follow PEP 8** for all Python code
- **Line length**: Max 100 characters (configured in pyproject.toml)
- **Imports**: Organized with `isort` (stdlib, third-party, local)
- **Formatting**: Use `black` for consistent formatting

### Documentation Style
- **Docstrings**: Use Google-style docstrings
- **Comments**: Explain *why*, not *what*
- **Type hints**: Include for function parameters and returns

### Example:
```python
from typing import Dict, Any, Optional


def analyze_crypto_pattern(
    binary_data: bytes,
    pattern: str,
    use_quantum: bool = True,
    backend: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze binary for cryptographic patterns using quantum or classical search.
    
    This function scans binary data for known cryptographic constants and
    implementation patterns, optionally using quantum-assisted search algorithms
    for improved performance.
    
    Args:
        binary_data: The binary data to analyze
        pattern: The pattern to search for (hex string format)
        use_quantum: Whether to use quantum-assisted search. Defaults to True.
        backend: Quantum backend to use. If None, uses default simulator.
        
    Returns:
        Dictionary containing:
            - matches: List of pattern matches with offsets
            - confidence: Confidence score for each match (0.0-1.0)
            - metadata: Additional analysis metadata
            - performance: Timing and performance metrics
        
    Raises:
        ValueError: If pattern format is invalid
        RuntimeError: If quantum backend is unavailable
        
    Example:
        >>> data = open('binary.exe', 'rb').read()
        >>> results = analyze_crypto_pattern(data, 'aes_sbox')
        >>> print(f"Found {len(results['matches'])} matches")
    """
    # Implementation here
    pass
```

### Quantum Circuit Style
- **Qubit labels**: Use descriptive names (`search_register`, `ancilla_0`)
- **Gate comments**: Explain the purpose of each gate sequence
- **Circuit depth**: Document and optimize circuit depth
- **Measurements**: Clearly label measurement outcomes

---

## Areas We Need Help With

### High Priority

#### CLI Enhancements
- Add more helpful error messages
- Implement progress bars for long operations
- Add colorized output for different message types
- Create interactive configuration wizard

#### Binary Loading
- Implement ELF parser using LIEF
- Add PE format support
- Create Mach-O loader
- Add binary format auto-detection

#### Quantum Engine
- Implement basic Grover's search circuit
- Add quantum backend management
- Create quantum/classical hybrid execution
- Optimize circuit depth and gate count

#### Testing Infrastructure
- Set up pytest framework
- Add unit tests for core modules
- Create integration tests for CLI
- Add quantum circuit validation tests

### Medium Priority

#### Analysis Features
- Implement disassembly using Capstone
- Add control flow graph generation
- Create data flow analysis
- Pattern matching optimization

#### Cryptanalysis
- Build crypto constants database
- Implement AES detection
- Add RSA key detection
- Create hash function identification

#### Integration
- Add YARA rule support
- Integrate with radare2
- Create Volatility plugins
- Add IDA Pro export

### Nice to Have

#### User Interface
- Web-based GUI using React
- Terminal UI with Textual
- VS Code extension
- Binary Ninja plugin

#### Advanced Features
- Machine learning integration
- Quantum machine learning algorithms
- Cloud quantum backend optimization
- Distributed analysis capabilities

---

## Research Opportunities

If you're interested in academic research collaboration:

### Active Research Areas
- **Quantum Cryptanalysis**: Exploring quantum algorithms for breaking classical encryption
- **Post-Quantum Security**: Analyzing PQC implementations in binaries
- **Quantum Forensics**: Developing new forensic techniques using quantum computing
- **Hybrid Analysis**: Combining quantum and classical methods optimally
- **Algorithm Optimization**: Improving quantum circuit efficiency

### Publishing Opportunities
- Conference papers (USENIX Security, Black Hat, DEF CON)
- Academic journals (IEEE Security & Privacy, ACM Computing Surveys)
- Technical blog posts and tutorials
- Open-source tool demonstrations

Contact the UTSA Cyber Jedis team if you'd like to collaborate on research papers or presentations!

---

## Communication

### Get in Touch
- **GitHub Issues**: For bugs, features, and technical discussion
- **GitHub Discussions**: For questions, ideas, and community chat
- **UTSA Cyber Jedis**: Reach out through the Discord in RowdyLink! (https://rowdylink.utsa.edu/organization/cyberjedis)
- **Email**: keeban.villarreal@my.utsa.edu

### Response Time
We're students and researchers, so please be patient! We aim to:
- Acknowledge issues within 48 hours
- Review pull requests within one week
- Provide meaningful feedback on all contributions

---

## Pull Request Process

### Before Submitting
1. ✅ Code follows PEP 8 and project style
2. ✅ All functions have docstrings
3. ✅ Type hints are included
4. ✅ Tests pass (if applicable)
5. ✅ Documentation is updated
6. ✅ Commit messages are clear

### PR Description Template
```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes Made
- List of specific changes
- Each on its own line

## Testing
How was this tested?

## Related Issues
Fixes #123
Related to #456

## Screenshots (if applicable)
```

### Review Process
1. Automated checks run (when CI/CD is set up)
2. Maintainer reviews code
3. Feedback provided if changes needed
4. Approval and merge when ready

---

## Recognition

All contributors will be:
- Listed in our CONTRIBUTORS.md file
- Credited in release notes
- Acknowledged in any academic publications using their contributions

---

## Code of Conduct

### Our Pledge
The UTSA Cyber Jedis believe in:
- **Respect**: Treat everyone with dignity and professionalism
- **Inclusion**: Welcome contributors from all backgrounds and skill levels
- **Learning**: Support each other's growth and education
- **Security**: Practice responsible disclosure of vulnerabilities
- **Collaboration**: Work together to advance the field
- **Openness**: Share knowledge and help others succeed

### Unacceptable Behavior
- Harassment or discrimination of any kind
- Malicious use of Zetton for illegal activities
- Disclosure of security vulnerabilities without proper coordination
- Plagiarism or copyright violation
- Aggressive or dismissive behavior

## Legal Stuff

### Licensing
By contributing to Zetton, you agree that:
- Your contributions will be licensed under the MIT License
- You have the right to contribute the code/content
- You understand this tool is for authorized security research only
- You will not include proprietary or copyrighted code without permission

### Responsible Use
Zetton is a security research tool. Contributors and users must:
- Use the tool only for authorized testing and research
- Respect applicable laws and regulations
- Practice responsible disclosure for vulnerabilities
- Not use the tool for malicious purposes

---

## Getting Started Checklist

Ready to contribute? Follow this checklist:

### Setup
- [ ] Fork the Zetton repository on GitHub
- [ ] Clone your fork locally
- [ ] Set up virtual environment (`python3 -m venv zetton-dev`)
- [ ] Activate environment (`source zetton-dev/bin/activate`)
- [ ] Install Zetton (`pip install -e ".[all]"`)
- [ ] Verify installation (`zetton status`)

### Preparation
- [ ] Read through README.md and INSTALLATION.md
- [ ] Explore the codebase structure
- [ ] Look at existing issues for ideas
- [ ] Check out the roadmap for priorities

### Development
- [ ] Create a feature branch
- [ ] Write your code
- [ ] Add docstrings and comments
- [ ] Test your changes
- [ ] Update documentation if needed

### Submission
- [ ] Commit with clear message
- [ ] Push to your fork
- [ ] Create pull request with description
- [ ] Respond to review feedback
- [ ] Celebrate your contribution! 🎉

---

## Frequently Asked Questions

### Q: I'm new to quantum computing. Can I still contribute?
**A:** Absolutely! There's plenty of work in classical analysis, CLI improvements, documentation, and testing. Learn quantum concepts as you go!

### Q: I'm new to Python. Is this too advanced?
**A:** The project follows standard Python practices. Start with documentation or simple bug fixes, and ask questions!

### Q: Do I need access to quantum hardware?
**A:** No! Zetton works with local quantum simulators. Qiskit Aer provides everything you need for development.

### Q: How long does review take?
**A:** We aim for one week, but may be faster or slower depending on complexity and our schedules.

### Q: Can I work on something not in the roadmap?
**A:** Yes! Open an issue to discuss your idea first, so we can provide guidance and avoid duplicate work.

### Q: I found a security vulnerability. What do I do?
**A:** Email keeban.villarreal@my.utsa.edu with details.

---

## Questions?

Don't hesitate to ask! We're here to help:
- Open a GitHub Discussion for general questions
- Comment on relevant issues for specific topics
- Reach out to the UTSA Cyber Jedis team
- Email us directly

**May the Source be with you!**

---

*Last updated: February 2026*  
*UTSA Cyber Jedis Quantum Cybersecurity Team*

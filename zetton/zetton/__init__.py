"""
Zetton - Quantum-Assisted Binary Analysis Framework for Digital Forensics

Zetton combines classical reverse engineering techniques with quantum computing
algorithms to provide enhanced binary analysis capabilities for security researchers
and digital forensics investigators.
"""

__version__ = "0.1.0"
__author__ = "Zetton Contributors"

from zetton.core.binary import Binary
from zetton.core.project import Project
from zetton.quantum.engine import QuantumEngine

__all__ = [
    "Binary",
    "Project", 
    "QuantumEngine",
    "__version__",
]


class Zetton:
    """
    Main entry point for Zetton framework.
    
    Provides a unified interface for loading binaries, performing analysis,
    and leveraging quantum-assisted techniques.
    
    Example:
        >>> from zetton import Zetton
        >>> z = Zetton("path/to/binary")
        >>> z.analyze()
        >>> print(z.crypto_findings)
    """
    
    def __init__(self, binary_path: str | None = None, project_name: str | None = None):
        """
        Initialize Zetton framework.
        
        Args:
            binary_path: Path to binary file to analyze
            project_name: Optional name for the analysis project
        """
        self.project = Project(name=project_name)
        self.binary: Binary | None = None
        self.quantum_engine = QuantumEngine()
        
        if binary_path:
            self.load(binary_path)
    
    def load(self, binary_path: str) -> "Zetton":
        """
        Load a binary file for analysis.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            Self for method chaining
        """
        self.binary = Binary.from_file(binary_path)
        self.project.add_binary(self.binary)
        return self
    
    def analyze(self, quantum_enabled: bool = True) -> dict:
        """
        Perform comprehensive analysis on the loaded binary.
        
        Args:
            quantum_enabled: Whether to use quantum-assisted techniques
            
        Returns:
            Dictionary containing analysis results
        """
        if self.binary is None:
            raise ValueError("No binary loaded. Call load() first.")
        
        results = {
            "binary_info": self.binary.info(),
            "sections": self.binary.sections,
            "symbols": self.binary.symbols,
        }
        
        # Classical analysis
        from zetton.analyzers.disasm import Disassembler
        disasm = Disassembler(self.binary)
        results["disassembly"] = disasm.disassemble()
        
        # Crypto identification
        from zetton.crypto.identify import CryptoIdentifier
        crypto_id = CryptoIdentifier(self.binary)
        results["crypto"] = crypto_id.identify(
            quantum_assist=quantum_enabled,
            quantum_engine=self.quantum_engine if quantum_enabled else None
        )
        
        return results
    
    @property
    def crypto_findings(self) -> list:
        """Get cryptographic findings from the most recent analysis."""
        if not hasattr(self, "_last_analysis"):
            return []
        return self._last_analysis.get("crypto", [])

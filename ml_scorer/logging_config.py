"""
Shared logging configuration for the ML Scorer service.
"""
import logging


def setup_logging(name=None):
    """
    Configure logging with consistent format across the application.
    
    Args:
        name: Module name for the logger. If None, returns root logger.
    
    Returns:
        Logger instance configured with standard format.
    """
    # Configure basicConfig only once (force=True in Python 3.8+ allows reconfiguration)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True
    )
    return logging.getLogger(name)

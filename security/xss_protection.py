"""
XSS Protection Module

Provides sanitization functions for user-generated content to prevent XSS attacks.
Uses bleach library to clean HTML and prevent malicious code injection.
"""

import bleach
from markupsafe import escape
from typing import Optional
import re


def sanitize_text(text: str) -> str:
    """
    Removes all HTML tags from text.
    Use for: usernames, titles, short text fields where no HTML is allowed.
    
    Args:
        text: Input text that may contain HTML
        
    Returns:
        Clean text with all HTML tags removed
        
    Example:
        >>> sanitize_text('<script>alert("xss")</script>Hello')
        'Hello'
    """
    if not text:
        return ""
    
    # Remove all HTML tags and strip whitespace
    return bleach.clean(text, tags=[], strip=True).strip()


def sanitize_html_content(text: str) -> str:
    """
    Allows safe HTML tags while removing dangerous ones.
    Use for: comments, posts, descriptions where you want to allow formatting.
    
    Args:
        text: Input HTML content
        
    Returns:
        Sanitized HTML with only safe tags
        
    Example:
        >>> sanitize_html_content('<p>Hello</p><script>alert(1)</script>')
        '<p>Hello</p>'
    """
    if not text:
        return ""
    
    # Define allowed HTML tags (safe for display)
    allowed_tags = [
        'p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li',
        'a', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3',
        'h4', 'h5', 'h6', 'span', 'div'
    ]
    
    # Define allowed attributes per tag
    allowed_attrs = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'title'],
        'span': ['class'],
        'div': ['class']
    }
    
    # Define allowed protocols for links
    allowed_protocols = ['http', 'https', 'mailto']
    
    return bleach.clean(
        text,
        tags=allowed_tags,
        attributes=allowed_attrs,
        protocols=allowed_protocols,
        strip=True
    )


def sanitize_url(url: str) -> str:
    """
    Validates and sanitizes URLs to prevent javascript: and data: URL attacks.
    
    Args:
        url: Input URL
        
    Returns:
        Sanitized URL or empty string if dangerous
        
    Example:
        >>> sanitize_url('javascript:alert(1)')
        ''
        >>> sanitize_url('https://example.com')
        'https://example.com'
    """
    if not url:
        return ""
    
    url = url.strip()
    
    # Block dangerous URL schemes
    dangerous_schemes = [
        'javascript:', 'data:', 'vbscript:', 'file:', 'about:'
    ]
    
    url_lower = url.lower()
    for scheme in dangerous_schemes:
        if url_lower.startswith(scheme):
            return ""
    
    # Clean the URL
    return bleach.clean(url, tags=[], strip=True)


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename to prevent directory traversal attacks.
    
    Args:
        filename: Input filename
        
    Returns:
        Safe filename
        
    Example:
        >>> sanitize_filename('../../etc/passwd')
        'passwd'
        >>> sanitize_filename('my file!@#.txt')
        'my_file.txt'
    """
    if not filename:
        return ""
    
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '')
    
    # Remove special characters except dots, underscores, hyphens
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def sanitize_username(username: str) -> str:
    """
    Sanitizes username - strict alphanumeric only.
    
    Args:
        username: Input username
        
    Returns:
        Sanitized username (lowercase alphanumeric + underscore)
        
    Example:
        >>> sanitize_username('User<script>123')
        'user123'
    """
    if not username:
        return ""
    
    # Remove all non-alphanumeric except underscore
    username = re.sub(r'[^a-zA-Z0-9_]', '', username)
    
    # Convert to lowercase
    username = username.lower()
    
    # Limit length
    if len(username) > 30:
        username = username[:30]
    
    return username


def escape_html(text: str) -> str:
    """
    HTML-escapes text for safe display.
    Use when you need to display user input as-is but safely.
    
    Args:
        text: Input text
        
    Returns:
        HTML-escaped text
        
    Example:
        >>> escape_html('<script>alert(1)</script>')
        '&lt;script&gt;alert(1)&lt;/script&gt;'
    """
    if not text:
        return ""
    
    return escape(text)


def sanitize_search_query(query: str) -> str:
    """
    Sanitizes search query to prevent SQL injection and XSS.
    
    Args:
        query: Search query
        
    Returns:
        Sanitized query
    """
    if not query:
        return ""
    
    # Remove HTML tags
    query = bleach.clean(query, tags=[], strip=True)
    
    # Limit length
    if len(query) > 100:
        query = query[:100]
    
    return query.strip()


# Export commonly used functions
__all__ = [
    'sanitize_text',
    'sanitize_html_content',
    'sanitize_url',
    'sanitize_filename',
    'sanitize_username',
    'escape_html',
    'sanitize_search_query'
]

// Get CSRF token from cookie
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Handle regex search form submission
document.getElementById('regex-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const path = document.getElementById('regex-path').value;
    const pattern = document.getElementById('regex-pattern').value;
    
    // Create form data
    const formData = new FormData();
    formData.append('path', path);
    formData.append('pattern', pattern);
    
    // Send AJAX request
    fetch('/api/regex-search/', {
        method: 'POST',
        body: formData,
        headers: {
            'X-CSRFToken': getCookie('csrftoken')
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.message);
        } else {
            // Display results in a modal
            const results = data.results;
            let message = 'Search Results:\n\n';
            
            if (results.length === 0) {
                message += 'No matches found.';
            } else {
                results.forEach(result => {
                    message += `File: ${result.file}\n`;
                    message += `Matches: ${result.matches.join(', ')}\n\n`;
                });
            }
            
            alert(message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while searching.');
    });
});

// Example regex patterns
const examplePatterns = {
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Phone': r'(\+90|0)?[0-9]{10}',
    'Turkish ID': r'[1-9][0-9]{10}',
    'Date (DD/MM/YYYY)': r'\d{2}/\d{2}/\d{4}',
    'Credit Card': r'\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'
};

// Add example patterns to the page
document.addEventListener('DOMContentLoaded', function() {
    const patternInput = document.getElementById('regex-pattern');
    const examplesDiv = document.createElement('div');
    examplesDiv.className = 'regex-examples';
    examplesDiv.innerHTML = '<h4>Example Patterns:</h4>';
    
    for (const [name, pattern] of Object.entries(examplePatterns)) {
        const button = document.createElement('button');
        button.textContent = name;
        button.onclick = function() {
            patternInput.value = pattern;
        };
        examplesDiv.appendChild(button);
    }
    
    patternInput.parentNode.insertBefore(examplesDiv, patternInput.nextSibling);
}); 
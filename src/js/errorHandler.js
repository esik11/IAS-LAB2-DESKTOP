// Global error handler for script loading and runtime errors
window.onerror = function(msg, url, lineNo, columnNo, error) {
    console.error('Error Details:', {
        message: msg,
        url: url,
        line: lineNo,
        column: columnNo,
        error: error
    });
    return false;
};

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled Promise Rejection:', event.reason);
});

// Handle script loading errors
document.addEventListener('DOMContentLoaded', function() {
    const scripts = document.getElementsByTagName('script');
    for (let script of scripts) {
        script.onerror = function() {
            console.error('Failed to load script:', script.src);
        };
    }
}); 
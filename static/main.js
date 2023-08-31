// Function to refresh token
// ... (existing code)

// Function to validate form fields
// ... (existing code)

// Function to fetch budget vs actual image
const fetchBudgetVsActualImage = () => {
    const month = document.getElementById('month-select').value;
    const year = document.getElementById('year-select').value;

    fetch(`/get_budget_vs_actual_image/${month}/${year}`)
        .then(response => response.json())
        .then(data => {
            if (data.image_data) {
                document.getElementById('budget-actual-chart').src = data.image_data;
            } else {
                console.error('Could not fetch image data');
            }
        })
        .catch(error => console.error('Fetch failed:', error));
};

document.addEventListener("DOMContentLoaded", function() {
    // Existing code for login and logout
    // ...

    // Add a click event listener to the button that triggers the image fetch
    const fetchImageBtn = document.getElementById('fetch-image-btn');
    if (fetchImageBtn) {
        fetchImageBtn.addEventListener("click", fetchBudgetVsActualImage);
    }

    // Refresh token every 15 minutes
    setInterval(refreshToken, 15 * 60 * 1000);
});

// Check if we are on the registration page
if ($("#registration-page").length) {

  // Code specific to the registration page
  $(document).ready(function() {

    // Attach click event to the Register button
    $("#register-btn").click(function() {

      // Perform some client-side validation
      let username = $("#username").val();
      let password = $("#password").val();

      if (username.length < 5) {
        alert("Username must be at least 5 characters.");
        return false;  // Prevent form submission
      }

      if (password.length < 8) {
        alert("Password must be at least 8 characters.");
        return false;  // Prevent form submission
      }

      // If validation passes, the form will be submitted
    });
  });
}

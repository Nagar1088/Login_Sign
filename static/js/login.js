  document.addEventListener('DOMContentLoaded', function() {
      // Phone number validation
      const phoneInput = document.querySelector('input[name="phone"]');
      if (phoneInput) {
          phoneInput.addEventListener('input', function(e) {
              this.value = this.value.replace(/[^0-9+]/g, '');
          });
      }

      // Password validation
      const passwordInput = document.querySelector('input[name="pswd"]');
      if (passwordInput) {
          passwordInput.addEventListener('input', function(e) {
              if (this.value.length < 8) {
                  this.setCustomValidity('Password must be at least 8 characters');
              } else {
                  this.setCustomValidity('');
              }
          });
      }
  });
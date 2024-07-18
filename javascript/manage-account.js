function toggleMenu() {
    var dropdown = document.getElementById("dashboard-account-dropdown");
    dropdown.classList.toggle("show");
}

function toggleEdit() {
    var usernameInput = document.getElementById("username");
    var editButton = document.getElementById("editButton");
    var messageDiv = document.getElementById("message");

    if (usernameInput.disabled) {
        usernameInput.disabled = false;
        usernameInput.style.backgroundColor = '#fff';
        usernameInput.style.color = '#000'; 
        editButton.textContent = 'Confirm'; 
        setTimeout(function() {
            usernameInput.focus();
            usernameInput.setSelectionRange(usernameInput.value.length, usernameInput.value.length);
        }, 0); 
        messageDiv.textContent = ''; 
        messageDiv.className = 'message'; 
    } else {
        updateUsername(usernameInput.value)
            .then(response => {
                if (response.message === "Username updated successfully") {
                    messageDiv.textContent = "Success, username changed. Logging out...";
                    messageDiv.className = 'message success';
                    setTimeout(() => {
                        window.location.href = "/logout"; 
                    }, 2000); 
                } else {
                    messageDiv.textContent = response.error;
                    messageDiv.className = 'message error';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                messageDiv.textContent = 'An error occurred. Please try again.';
                messageDiv.className = 'message error';
            });
    }
}

async function updateUsername(newUsername) {
    const response = await fetch('/update-username', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ new_username: newUsername })
    });
    return response.json();
}
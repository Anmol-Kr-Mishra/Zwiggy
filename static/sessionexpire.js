// Set your session timeout duration (in milliseconds)
const SESSION_TIMEOUT = 10000*60 * 1000; // 10000 minute

// Initialize session start time if not already set
if (!sessionStorage.getItem("sessionStartTime")) {
  const currentTime = new Date().getTime();
  sessionStorage.setItem("sessionStartTime", currentTime);
}

// Check session timeout
const checkTimeout = () => {
  const sessionStartTime = parseInt(sessionStorage.getItem("sessionStartTime"));
  if (isNaN(sessionStartTime)) {
    console.error("Session start time is invalid or not set.");
    return;
  }

  const currentTime = new Date().getTime();
  const elapsedTime = currentTime - sessionStartTime;

  if (elapsedTime > SESSION_TIMEOUT) {
    alert("Your session has expired. Redirecting to logout...");
    sessionStorage.removeItem("sessionStartTime");
    window.location.replace("/logout/"); // Redirect to logout route
  } else {
    // Schedule the next check
    setTimeout(checkTimeout, Math.min(SESSION_TIMEOUT - elapsedTime, 5000));
  }
};

// Start the timeout check
checkTimeout();

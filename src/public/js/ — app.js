async function sendForm(url, data) {
	const response = await fetch(url, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		credentials: "same-origin",
		body: JSON.stringify(data)
	});

	const result = await response.json();

	if (!response.ok) {
		throw new Error(result.error || "Something went wrong.");
	}

	return result;
}

const registerForm = document.getElementById("registerForm");

if (registerForm) {
	registerForm.addEventListener("submit", async event => {
		event.preventDefault();

		const form = new FormData(registerForm);
		const message = document.getElementById("message");

		try {
			await sendForm("/api/register", {
				name: form.get("name"),
				email: form.get("email"),
				password: form.get("password")
			});

			message.textContent = "Account created. You can now log in.";
			registerForm.reset();
		} catch (error) {
			message.textContent = error.message;
		}
	});
}

const loginForm = document.getElementById("loginForm");

if (loginForm) {
	loginForm.addEventListener("submit", async event => {
		event.preventDefault();

		const form = new FormData(loginForm);
		const message = document.getElementById("message");

		try {
			const result = await sendForm("/api/login", {
				email: form.get("email"),
				password: form.get("password")
			});

			window.location.href =
				result.user.role === "admin" ? "/admin.html" : "/dashboard.html";
		} catch (error) {
			message.textContent = error.message;
		}
	});
}

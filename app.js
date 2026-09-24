function showLogin(type, button) {
    document.getElementById("admin-login").classList.toggle("hidden", type !== "admin");
    document.getElementById("customer-login").classList.toggle("hidden", type !== "customer");

    document.querySelectorAll(".tab").forEach(function(tab) {
        tab.classList.remove("active");
    });
    button.classList.add("active");
}

function validateCreate() {
    const pin = document.getElementById("create-pin").value;
    if (!/^\d{4}$/.test(pin)) {
        alert("PIN must contain exactly 4 digits.");
        return false;
    }
    return true;
}

function validateAmount(id) {
    const amount = Number(document.getElementById(id).value);
    if (!Number.isFinite(amount) || amount <= 0) {
        alert("Enter an amount greater than 0.");
        return false;
    }
    return true;
}

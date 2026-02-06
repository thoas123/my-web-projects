function initializeModal() {
    // --- Spinner Logic ---
    const spinnerHTML = `
        <div id="spinner-overlay" class="spinner-overlay">
            <div class="spinner"></div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', spinnerHTML);
    const spinnerOverlay = document.getElementById('spinner-overlay');

    window.showSpinner = function() {
        if (spinnerOverlay) spinnerOverlay.style.display = 'flex';
    };
    window.hideSpinner = function() {
        if (spinnerOverlay) spinnerOverlay.style.display = 'none';
    };

    const modalHTML = `
        <div id="modal" class="modal-overlay">
            <div class="modal-content">
                <p id="modal-message"></p>
                <div id="modal-actions"></div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    const modal = document.getElementById('modal');
    const modalMessage = document.getElementById('modal-message');
    const modalActions = document.getElementById('modal-actions');

    window.showMessage = function(message) {
        modalMessage.textContent = message;
        modalActions.innerHTML = `<button class="btn-ok">OK</button>`;
        modal.style.display = 'flex';
        modal.querySelector('.btn-ok').onclick = () => modal.style.display = 'none';
    };

    window.showConfirmation = function(message) {
        return new Promise(resolve => {
            modalMessage.textContent = message;
            modalActions.innerHTML = `<button class="btn-confirm">Yes</button><button class="btn-cancel">No</button>`;
            modal.style.display = 'flex';
            modal.querySelector('.btn-confirm').onclick = () => { modal.style.display = 'none'; resolve(true); };
            modal.querySelector('.btn-cancel').onclick = () => { modal.style.display = 'none'; resolve(false); };
        });
    };

    window.showPhonePrompt = function(message) {
        return new Promise(resolve => {
            modalMessage.textContent = message;
            modalActions.innerHTML = `
                <p id="phone-error" style="color: red; font-size: 0.9rem; display: none;"></p>
                <input type="tel" id="phone-input" placeholder="254712345678">
                <button class="btn-confirm">Submit</button>
                <button class="btn-cancel">Cancel</button>
            `;
            modal.style.display = 'flex';
            const phoneInput = document.getElementById('phone-input');
            const phoneError = document.getElementById('phone-error');

            modal.querySelector('.btn-confirm').onclick = () => {
                const phone = phoneInput.value;
                if (!/^254\d{9}$/.test(phone)) {
                    phoneInput.style.border = '1px solid red';
                    phoneError.textContent = "Invalid format. Use 2547xxxxxxxx.";
                    phoneError.style.display = 'block';
                } else {
                    modal.style.display = 'none';
                    resolve(phone);
                }
            };
            modal.querySelector('.btn-cancel').onclick = () => { modal.style.display = 'none'; resolve(null); };
        });
    };
}

document.addEventListener('DOMContentLoaded', initializeModal);
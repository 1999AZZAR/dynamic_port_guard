// Simple Modal Popup Utility
function openModal(title, contentHtml) {
    let modal = document.getElementById('custom-modal');
    if (!modal) return; // Modal must exist in DOM
    // Set content
    modal.innerHTML = `
        <div class="bg-white rounded-2xl shadow-xl max-w-2xl w-full mx-4 overflow-hidden flex flex-col" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between px-6 py-4 border-b">
                <h3 class="text-lg font-semibold text-gray-800">${title}</h3>
                <button onclick="closeModal()" class="text-gray-400 hover:text-gray-700"><span class="material-icons">close</span></button>
            </div>
            <div class="p-6 overflow-y-auto max-h-[70vh]" id="modal-content">${contentHtml}</div>
        </div>
    `;
    modal.classList.remove('hidden');
    // Close when clicking outside modal
    modal.onclick = function() { closeModal(); };
}
function closeModal() {
    const modal = document.getElementById('custom-modal');
    if (modal) modal.classList.add('hidden');
}
window.openModal = openModal;
window.closeModal = closeModal;

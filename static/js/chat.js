document.addEventListener('DOMContentLoaded', function () {
  const chatForm = document.getElementById('chat-form');
  const messageInput = document.getElementById('message-input');
  const chatHistory = document.getElementById('chat-history');
  const loadingSpinner = document.getElementById('loading-spinner');
  const fileInput = document.getElementById('file-input');
  const csrfToken = document.querySelector('meta[name=csrf-token]')?.getAttribute('content');

  const chatId = chatHistory?.dataset.chatId;
  let lastId = 0;

  if (chatHistory) {
    chatHistory.scrollTop = chatHistory.scrollHeight;
    const bubbles = chatHistory.querySelectorAll('.chat-bubble');
    bubbles.forEach(bubble => {
      const id = parseInt(bubble.dataset.id, 10);
      if (!isNaN(id)) lastId = Math.max(lastId, id);
    });
  }

  async function appendMessages(messages) {
    if (!Array.isArray(messages)) return;

    messages.forEach((msg) => {
      if (msg.id <= lastId) return;

      const wrapper = document.createElement('div');
      wrapper.classList.add('d-flex', 'mb-3', msg.role === 'user' ? 'justify-content-end' : 'justify-content-start');

      const bubble = document.createElement('div');
      bubble.classList.add('p-3', 'rounded', 'shadow-sm');
      bubble.classList.add(msg.role === 'user' ? 'bg-primary' : 'bg-light');
      bubble.classList.add(msg.role === 'user' ? 'text-white' : 'text-dark');
      bubble.style.maxWidth = '70%';
      bubble.dataset.id = msg.id;

      if (msg.content) {
        const mdContainer = document.createElement('div');
        mdContainer.className = 'mb-2';

        mdContainer.innerHTML = marked.parse(msg.content || '');

        bubble.appendChild(mdContainer);
      }

      if (msg.role !== 'user') {
        const actions = document.createElement('div');
        actions.className = 'msg-actions mt-2 d-flex gap-2';

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'btn btn-sm btn-link text-decoration-none btn-copy';
        copyBtn.title = 'Copy';
        copyBtn.innerHTML = '<i class="fas fa-copy"></i>';

        const ttsBtn = document.createElement('button');
        ttsBtn.type = 'button';
        ttsBtn.className = 'btn btn-sm btn-link text-decoration-none btn-tts';
        ttsBtn.title = 'Listen';
        ttsBtn.setAttribute('data-state', 'idle');
        ttsBtn.innerHTML = '<i class="fas fa-volume-up"></i>';

        actions.appendChild(copyBtn);
        actions.appendChild(ttsBtn);
        bubble.appendChild(actions);
      }

      if (msg.file_path) {
        const names = msg.file_path.split(',').map(s => s.trim()).filter(Boolean);
        if (names.length) {
          const attWrap = document.createElement('div');
          attWrap.className = 'mt-2';
          renderAttachmentGallery(attWrap, names);
          bubble.appendChild(attWrap);
        }
      }

      const small = document.createElement('small');
      small.classList.add('text-muted', 'd-block', 'text-end', 'mt-2');
      small.style.fontSize = '0.7rem';
      small.innerHTML = msg.created_at ? msg.created_at : '&nbsp;';
      bubble.appendChild(small);

      wrapper.appendChild(bubble);
      chatHistory.appendChild(wrapper);
      chatHistory.scrollTop = chatHistory.scrollHeight;
      lastId = Math.max(lastId, msg.id);
    });
  }
  const sendBtn = chatForm.querySelector('button[type="submit"]');
  chatForm?.addEventListener('submit', async function (e) {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text && (!fileInput || !fileInput.files.length)) return;

    if (loadingSpinner) loadingSpinner.style.display = 'block';
    if (sendBtn) sendBtn.disabled = true;

    const formData = new FormData();
    formData.append('message', text);
    if (fileInput && fileInput.files.length) {
      for (const file of fileInput.files) formData.append('files', file);
    }

    try {
      const response = await fetch(chatForm.action, {
        method: 'POST',
        body: formData,
        headers: csrfToken ? { 'X-CSRFToken': csrfToken } : {},
      });
      if (!response.ok) throw new Error('Failed to send message');

      const data = await response.json();
      if (data.messages) await appendMessages(data.messages);

      messageInput.value = '';
      if (fileInput) fileInput.value = '';
      if (previewWrap) previewWrap.innerHTML = '';
    } catch (err) {
      console.error(err);
      alert('An error occurred while sending your message.');
    } finally {
      if (loadingSpinner) loadingSpinner.style.display = 'none';
      if (sendBtn) sendBtn.disabled = false;
    }
  });

});

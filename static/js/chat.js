document.addEventListener('DOMContentLoaded', function () {
  const chatForm = document.getElementById('chat-form');
  const messageInput = document.getElementById('message-input');
  const chatHistory = document.getElementById('chat-history');
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

  chatHistory?.addEventListener('click', async (e) => {
    const likeBtn = e.target.closest('.btn-like');
    const dislikeBtn = e.target.closest('.btn-dislike');

    if (likeBtn) {
      try {
        const resp = await fetch(`/feedback/like`, {
          method: 'POST',
          headers: { 'X-CSRFToken': csrfToken }
        });
        const data = await resp.json();
        if (data.success) {
          showFlash('success', data.message || "Thanks for your feedback 🙌");
        }
      } catch (err) {
        console.error(err);
        showFlash('danger', "Failed to send like feedback");
      }
    }

    if (dislikeBtn) {
      const modal = new bootstrap.Modal(document.getElementById('feedbackModal'));
      modal.show();
    }
  });

  document.getElementById('dislike-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const reasons = Array.from(form.querySelectorAll('input[name="reasons"]:checked')).map(el => el.value);
    const comments = form.querySelector('textarea[name="comments"]').value;

    try {
      const resp = await fetch(`/feedback/dislike`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ reasons, comments })
      });

      const data = await resp.json();
      if (data.success) {
        const modalEl = document.getElementById('feedbackModal');
        bootstrap.Modal.getInstance(modalEl).hide();
        showFlash('success', data.message || "Thanks for helping us improve 💡");
      }
    } catch (err) {
      console.error(err);
      showFlash('danger', "Failed to send dislike feedback");
    }
  });

  function showFlash(type, message) {
    const flash = document.createElement('div');
    flash.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
    flash.style.zIndex = 2000;
    flash.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;
    document.body.appendChild(flash);
    setTimeout(() => {
      if (flash && flash.parentNode) flash.remove();
    }, 4000);
  }

  async function appendMessages(messages) {
    if (!Array.isArray(messages)) return;

    messages.forEach((msg) => {
      if (msg.id <= lastId) return;

      const wrapper = document.createElement('div');
      wrapper.classList.add('d-flex', 'mb-3', msg.role === 'user' ? 'justify-content-end' : 'justify-content-start');

      const bubble = document.createElement('div');
      bubble.classList.add('p-3', 'rounded', 'shadow-sm');
      bubble.classList.add(msg.role === 'user' ? 'bg-click-user' : 'bg-light');
      bubble.classList.add(msg.role === 'user' ? 'text-dark' : 'text-dark');
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
        const likeBtn = document.createElement('button');
        likeBtn.type = 'button';
        likeBtn.className = 'btn btn-sm btn-link text-success text-decoration-none btn-like';
        likeBtn.title = 'Like';
        likeBtn.innerHTML = '<i class="fas fa-thumbs-up"></i>';

        const dislikeBtn = document.createElement('button');
        dislikeBtn.type = 'button';
        dislikeBtn.className = 'btn btn-sm btn-link text-danger text-decoration-none btn-dislike';
        dislikeBtn.title = 'Dislike';
        dislikeBtn.innerHTML = '<i class="fas fa-thumbs-down"></i>';

        actions.appendChild(likeBtn);
        actions.appendChild(dislikeBtn);

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

    if (sendBtn) sendBtn.disabled = true;

    const formData = new FormData();
    formData.append('message', text);
    if (fileInput && fileInput.files.length) {
      for (const file of fileInput.files) formData.append('files', file);
    }

    const thinkingId = `thinking-${Date.now()}`;
    const thinkingWrapper = document.createElement('div');
    thinkingWrapper.className = 'd-flex mb-3 justify-content-start';
    thinkingWrapper.id = thinkingId;

    const thinkingBubble = document.createElement('div');
    thinkingBubble.className = 'p-3 rounded shadow-sm ai-thinking-bubble text-dark';
    thinkingBubble.style.maxWidth = '70%';

    thinkingBubble.innerHTML = `
  <div style="font-weight:600; margin-bottom:6px;">Deep reasoning in progress <span class="ai-thinking-dots"></span></div>
`;

    thinkingWrapper.appendChild(thinkingBubble);
    chatHistory.appendChild(thinkingWrapper);
    chatHistory.scrollTop = chatHistory.scrollHeight;

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
      if (sendBtn) sendBtn.disabled = false;
      const existing = document.getElementById(thinkingId);
      if (existing) existing.remove();
    }
  });

});

/* ============================================================
   ZENMARKET — CONTACT MESSAGES
   DEMO_MODE=false → Supabase contact_messages table
   DEMO_MODE=true  → localStorage (zm_contact_messages)
   ============================================================ */
import { DEMO_MODE } from './config.js';

export const LS_KEY = 'zm_contact_messages';

async function _store() {
  if (DEMO_MODE) return null;
  return import('./supabase-store.js');
}

function _lsLoad() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || '[]').sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt)); }
  catch { return []; }
}
function _lsSave(arr) { localStorage.setItem(LS_KEY, JSON.stringify(arr)); }

export async function getMessages() {
  try {
    const store = await _store();
    if (store) return store.getContactMessages();
  } catch(e) { console.warn('getMessages:', e); }
  return _lsLoad();
}

export async function addMessage(fields) {
  const msg = {
    id: 'msg_' + Date.now() + '_' + Math.random().toString(36).slice(2,7),
    firstName: fields.firstName || '', lastName: fields.lastName || '',
    email: fields.email || '', phone: fields.phone || '',
    subject: fields.subject || '', message: fields.message || '',
    createdAt: new Date().toISOString(), read: false,
  };
  try {
    const store = await _store();
    if (store) {
      await store.saveContactMessage({
        id: msg.id, first_name: msg.firstName, last_name: msg.lastName,
        email: msg.email, phone: msg.phone, subject: msg.subject,
        message: msg.message, read: false,
      });
      return msg;
    }
  } catch(e) { console.warn('addMessage:', e); }
  const all = _lsLoad(); all.unshift(msg); _lsSave(all); return msg;
}

export async function markRead(id) {
  try {
    const store = await _store();
    if (store) { await store.markContactMessageRead(id); return; }
  } catch(e) { console.warn('markRead:', e); }
  const all = _lsLoad(); const idx = all.findIndex(m=>m.id===id);
  if (idx !== -1) { all[idx].read=true; _lsSave(all); }
}

export async function deleteMessage(id) {
  try {
    const store = await _store();
    if (store) { await store.deleteContactMessage(id); return; }
  } catch(e) { console.warn('deleteMessage:', e); }
  _lsSave(_lsLoad().filter(m=>m.id!==id));
}

export async function markAllRead() {
  try {
    const store = await _store();
    if (store) {
      const msgs = await store.getContactMessages();
      await Promise.all(msgs.filter(m=>!m.read).map(m=>store.markContactMessageRead(m.id)));
      return;
    }
  } catch(e) { console.warn('markAllRead:', e); }
  _lsSave(_lsLoad().map(m=>({...m,read:true})));
}

export async function unreadCount() {
  return (await getMessages()).filter(m=>!m.read).length;
}

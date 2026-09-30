const $=id=>document.getElementById(id),
AMAX=20*1048576,VMAX=50*1048576,SMAX=50*1048576,OMAX=100*1048576,
MAGIC=[83,84,71,49],FOOT=[83,84,71,70],
enc=new TextEncoder(),dec=new TextDecoder(),eq=(a,m)=>m.every((v,i)=>a[i]===v);

async function key(pw,salt){
  const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function seal(name,data,pw){
  const nb=enc.encode(name),plain=new Uint8Array(2+nb.length+data.length);
  new DataView(plain.buffer).setUint16(0,nb.length);plain.set(nb,2);plain.set(data,2+nb.length);
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),
  ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(pw,salt),plain)),
  blk=new Uint8Array(36+ct.length);
  blk.set(MAGIC);new DataView(blk.buffer).setUint32(4,28+ct.length,true);
  blk.set(salt,8);blk.set(iv,24);blk.set(ct,36);return blk;
}
async function open(blk,pw){
  let p;
  try{p=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:blk.slice(24,36)},await key(pw,blk.slice(8,24)),blk.slice(36)))}
  catch{throw Error('Kata sandi salah atau data rusak.')}
  const n=new DataView(p.buffer).getUint16(0);
  return{name:dec.decode(p.subarray(2,2+n)),data:p.subarray(2+n)};
}

function wav(b){
  const t=o=>String.fromCharCode(b[o],b[o+1],b[o+2],b[o+3]);
  if(b.length<44||t(0)!=='RIFF'||t(8)!=='WAVE')return null;
  const v=new DataView(b.buffer,b.byteOffset,b.length);let p=12,fmt=0,bits=0;
  while(p+8<=b.length){
    const id=t(p),sz=v.getUint32(p+4,true);
    if(id==='fmt '){fmt=v.getUint16(p+8,true);bits=v.getUint16(p+22,true)}
    if(id==='data')return fmt===1&&bits%8===0&&bits?{off:p+8,end:Math.min(b.length,p+8+sz),step:bits/8}:null;
    p+=8+sz+(sz&1);
  }
  return null;
}
const cap=w=>Math.floor((w.end-w.off)/w.step);
function lsbPut(b,w,blk){
  const o=b.slice(),s=w.step;let p=w.off;
  for(let i=0;i<blk.length;i++){const x=blk[i];for(let k=7;k>=0;k--,p+=s)o[p]=(o[p]&254)|((x>>k)&1)}
  return o;
}
function lsbGet(b,w){
  const s=w.step;let p=w.off;
  const rd=n=>{const o=new Uint8Array(n);for(let i=0;i<n;i++){let x=0;for(let k=0;k<8;k++,p+=s)x=(x<<1)|(b[p]&1);o[i]=x}return o};
  if(cap(w)<64)return null;
  const h=rd(8);if(!eq(h,MAGIC))return null;
  const len=new DataView(h.buffer).getUint32(4,true);
  if(len<29||(8+len)*8>cap(w))return null;
  const blk=new Uint8Array(8+len);blk.set(h);blk.set(rd(len),8);return blk;
}

function tail(b,blk){
  const n=b.length,o=new Uint8Array(n+blk.length+8);
  o.set(b);o.set(blk,n);o.set(FOOT,n+blk.length+4);
  new DataView(o.buffer).setUint32(n+blk.length,blk.length,true);return o;
}
function tailGet(b){
  const n=b.length;if(n<44||!eq(b.subarray(n-4),FOOT))return null;
  const len=new DataView(b.buffer,b.byteOffset,n).getUint32(n-8,true);
  if(len<36||len>n-8)return null;
  const blk=b.slice(n-8-len,n-8);return eq(blk,MAGIC)?blk:null;
}

const mb=n=>(n/1048576).toFixed(2)+' MB',
st=(id,m,c='')=>{const e=$(id);e.hidden=!m;e.textContent=m;e.className='st '+c},
bytes=async f=>new Uint8Array(await f.arrayBuffer());
let urls=[];
function dl(box,data,name,type){
  const u=URL.createObjectURL(new Blob([data],{type}));urls.push(u);
  const a=document.createElement('a');a.href=u;a.download=name;a.textContent='Unduh '+name;box.append(a);return u;
}
const isVideo=f=>/^video\//.test(f.type);
function checkMedia(f,label){
  if(!f)throw Error('Pilih '+label+' terlebih dahulu.');
  if(!/^(audio|video)\//.test(f.type))throw Error('File harus berformat audio atau video.');
  const max=isVideo(f)?VMAX:AMAX;
  if(f.size>max)throw Error(label+' ('+mb(f.size)+') melebihi batas '+mb(max)+' untuk '+(isVideo(f)?'video':'audio')+'.');
}
function checkSize(f,label,max){
  if(!f)throw Error('Pilih '+label+' terlebih dahulu.');
  if(f.size>max)throw Error(label+' ('+mb(f.size)+') melebihi batas '+mb(max)+'.');
}
async function run(btn,sid,fn){
  btn.disabled=true;st(sid,'Memproses…');
  try{await fn()}catch(e){st(sid,e.message,'er')}finally{btn.disabled=false}
}

$('go1').onclick=e=>run(e.target,'s1',async()=>{
  const c=$('carrier').files[0],s=$('sfile').files[0],t=$('text').value,pw=$('pw1').value,box=$('o1');
  box.replaceChildren();urls.splice(0).forEach(URL.revokeObjectURL);
  checkMedia(c,'file pembawa');
  if(s)checkSize(s,'file rahasia',SMAX);else if(!t)throw Error('Isi pesan rahasia atau pilih file rahasia.');
  if(pw.length<4)throw Error('Kata sandi minimal 4 karakter.');
  const cb=await bytes(c),blk=await seal(s?s.name:'',s?await bytes(s):enc.encode(t),pw),w=wav(cb);
  let out,how;
  if(w&&blk.length*8<=cap(w)){out=lsbPut(cb,w,blk);how='LSB pada sampel WAV (ukuran file tetap)'}
  else{out=tail(cb,blk);how='penyisipan di akhir container'}
  if(out.length>OMAX)throw Error('Hasil ('+mb(out.length)+') melebihi batas '+mb(OMAX)+'. Pakai file pembawa atau file rahasia yang lebih kecil.');
  const u=dl(box,out,'stego-'+c.name,c.type),m=document.createElement(c.type.startsWith('video')?'video':'audio');
  m.controls=true;m.src=u;box.prepend(m);
  st('s1','Berhasil. Metode: '+how+'. Ukuran hasil '+mb(out.length)+'.','ok');
});

$('go2').onclick=e=>run(e.target,'s2',async()=>{
  const f=$('stego').files[0],pw=$('pw2').value,box=$('o2');
  box.replaceChildren();urls.splice(0).forEach(URL.revokeObjectURL);
  checkMedia(f,'file stego');
  if(!pw)throw Error('Masukkan kata sandi.');
  const b=await bytes(f);let blk=tailGet(b);
  if(!blk){const w=wav(b);blk=w&&lsbGet(b,w)}
  if(!blk)throw Error('Tidak ditemukan data tersembunyi pada file ini.');
  const r=await open(blk,pw);
  if(r.name){dl(box,r.data,r.name,'application/octet-stream');st('s2','Berhasil. File rahasia: '+r.name+' ('+mb(r.data.length)+').','ok')}
  else{const p=document.createElement('pre');p.textContent=dec.decode(r.data);box.append(p);st('s2','Berhasil. Pesan rahasia:','ok')}
});

const tabs=[[$('t1'),$('p1')],[$('t2'),$('p2')]];
tabs.forEach(([t])=>t.onclick=()=>tabs.forEach(([x,p])=>{const on=x===t;x.setAttribute('aria-selected',on);p.hidden=!on}));

function wireClear(inputId){
  const inp=$(inputId),btn=document.querySelector('.clr[data-for="'+inputId+'"]');
  if(!inp||!btn)return;
  const sync=()=>{const f=inp.files[0];btn.hidden=!f;if(f)btn.textContent='✕ Hapus: '+f.name};
  inp.addEventListener('change',sync);
  btn.addEventListener('click',()=>{inp.value='';sync();inp.focus()});
  sync();
}
['carrier','sfile','stego'].forEach(wireClear);

window.addEventListener('load',()=>{
  const l=$('loader');if(!l)return;
  setTimeout(()=>{l.classList.add('hide');setTimeout(()=>l.remove(),600)},1400);
});

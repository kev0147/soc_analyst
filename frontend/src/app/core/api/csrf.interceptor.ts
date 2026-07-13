import { HttpInterceptorFn } from '@angular/common/http';

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') {
    return null;
  }
  const match = document.cookie
    .split(';')
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split('=').slice(1).join('=')) : null;
}

export const csrfInterceptor: HttpInterceptorFn = (request, next) => {
  const csrf = readCookie('csrftoken');
  const cloned = csrf
    ? request.clone({
        withCredentials: true,
        setHeaders: { 'X-CSRFToken': csrf },
      })
    : request.clone({ withCredentials: true });
  return next(cloned);
};

import { useAuthStore } from "~/store/authStore";
import { navigateTo, defineNuxtRouteMiddleware } from "#imports";

export default defineNuxtRouteMiddleware(async (to, from) => {
  // Avoid middleware runs on server for non-page requests
  if (import.meta.server && (!to.name || to.path.startsWith("/_nuxt/"))) return; // Use import.meta
  if (
    to.meta.public ||
    ["/login", "/register", "/auth/external-callback"].includes(to.path)
  )
    return;

  const authStore = useAuthStore();

  // Wait for auth init on client if navigating directly to protected route
  if (import.meta.client && !authStore.isInitialized) {
    // Use import.meta
    await new Promise<void>((resolve) => {
      /* ... Wait logic ... */
    });
  }

  const requiresAuth = to.meta.requiresAuth ?? true;
  const requiredRoles = to.meta.roles as string[] | undefined;

  if (requiresAuth && !authStore.isLoggedIn) {
    const redirect =
      to.fullPath !== "/" ? `?redirect=${encodeURIComponent(to.fullPath)}` : "";
    return navigateTo(`/login${redirect}`, { replace: true });
  }

  if (authStore.isLoggedIn && requiredRoles?.length) {
    // Simplified check
    const userRoles = authStore.user?.roles ?? [];
    const hasRequiredRole = requiredRoles.some((role) =>
      userRoles.includes(role)
    );
    if (!hasRequiredRole) {
      console.warn(`Auth Middleware: Role check failed for ${to.path}.`);
      return navigateTo("/forbidden", { replace: true }); // Defined forbidden page
    }
  }
});

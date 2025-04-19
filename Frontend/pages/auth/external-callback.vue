<script setup lang="ts">
import { useRoute, navigateTo, definePageMeta, onMounted } from "#imports";
import { useAuthStore } from "~/store/authStore";

// Ensure this page itself doesn't trigger auth middleware loops
definePageMeta({ public: true });

const route = useRoute();
const authStore = useAuthStore();

onMounted(async () => {
  const success = route.query.success === "true";
  const error = route.query.error as string | undefined;
  const returnUrl = (route.query.returnUrl as string) || "/";

  if (success) {
    // console.log("External callback success. Fetching user..."); // Debug log
    // Force re-check auth status to update Pinia state from cookies
    await authStore.fetchUser();
    // Redirect to intended destination or home
    await navigateTo(returnUrl, { external: false, replace: true });
  } else {
    // console.error("External callback failure:", error); // Debug log
    // Redirect back to login, passing the error message
    await navigateTo(
      `/login?error=${encodeURIComponent(error || "External login failed.")}`,
      { external: false, replace: true }
    );
  }
});
</script>

<template>
  <div>
    <p>Processing external login, please wait...</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useAuthStore } from "~/store/authStore";
import { useErrorStore } from "~/store/errorStore";
import { navigateTo, useRoute, useRuntimeConfig } from "#app";

const authStore = useAuthStore();
const errorStore = useErrorStore();
const route = useRoute();
const config = useRuntimeConfig();

// Form fields
const email = ref("");
const password = ref("");
const confirmPassword = ref("");

// Success message state
const successMessage = ref<string | null>(null);

// --- Registration Handler ---
const handleRegister = async () => {
  const passwordsMatch = password.value === confirmPassword.value;
  if (!passwordsMatch) {
    errorStore.setError({
      title: "Validation Error",
      errors: {
        ConfirmPassword: ["Passwords do not match."],
      },
    });
    return;
  }

  const success = await authStore.register({
    email: email.value,
    password: password.value,
    confirmPassword: confirmPassword.value,
  });

  if (success) {
    successMessage.value = "Registration successful! Please log in.";
    email.value = "";
    password.value = "";
    confirmPassword.value = "";
  }
};

// --- Google Login Handler ---
const handleGoogleLogin = () => {
  const backendChallengeUrl = `${config.public.apiBaseUrl}/auth/external-login?provider=Google`;
  window.location.href = backendChallengeUrl; // Redirect browser
};

// --- Display errors passed back from external callback (if redirected here) ---
onMounted(() => {
  const queryError = route.query.error as string;
  if (queryError) {
    errorStore.setError({
      title: "External Sign-In Failed",
      detail: queryError,
    });
  }
});
</script>

<template>
  <div>
    <h1>Register</h1>
    <form @submit.prevent="handleRegister">
      <div>
        <label for="email">Email:</label>
        <input
          type="email"
          id="email"
          v-model="email"
          required
          autocomplete="email"
        />
        <span
          v-if="
            errorStore.validationErrors?.Email ||
            errorStore.validationErrors?.email
          "
          class="error-text"
        >
          {{
            (
              errorStore.validationErrors?.Email ||
              errorStore.validationErrors?.email
            )?.join(", ")
          }}
        </span>
      </div>
      <div>
        <label for="password">Password:</label>
        <input
          type="password"
          id="password"
          v-model="password"
          required
          autocomplete="new-password"
        />
        <span
          v-if="
            errorStore.validationErrors?.Password ||
            errorStore.validationErrors?.password
          "
          class="error-text"
        >
          {{
            (
              errorStore.validationErrors?.Password ||
              errorStore.validationErrors?.password
            )?.join(", ")
          }}
        </span>
      </div>
      <div>
        <label for="confirmPassword">Confirm Password:</label>
        <input
          type="password"
          id="confirmPassword"
          v-model="confirmPassword"
          required
          autocomplete="new-password"
        />
        <span
          v-if="
            errorStore.validationErrors?.ConfirmPassword ||
            errorStore.validationErrors?.confirmPassword
          "
          class="error-text"
        >
          {{
            (
              errorStore.validationErrors?.ConfirmPassword ||
              errorStore.validationErrors?.confirmPassword
            )?.join(", ")
          }}
        </span>
      </div>

      <div
        v-if="successMessage"
        class="success-message"
        style="margin-top: 1rem"
      >
        {{ successMessage }} Go to <NuxtLink to="/login">Login</NuxtLink>.
      </div>

      <div
        v-if="errorStore.hasError && !errorStore.hasValidationErrors"
        class="error-message"
        style="margin-top: 1rem"
      >
        {{ errorStore.errorTitle }}: {{ errorStore.errorDetail }}
      </div>

      <button type="submit" :disabled="authStore.isLoading || !!successMessage">
        <span v-if="authStore.isLoading">Registering...</span>
        <span v-else>Register</span>
      </button>
    </form>

    <hr style="margin: 1rem 0" />

    <button
      @click="handleGoogleLogin"
      :disabled="authStore.isLoading || !!successMessage"
    >
      <span v-if="authStore.isLoading">Loading...</span>
      <span v-else>Sign up with Google</span>
    </button>

    <p style="margin-top: 1rem">
      Already have an account? <NuxtLink to="/login">Login here</NuxtLink>
    </p>
  </div>
</template>

<style scoped>
/* Add basic styling for errors/success */
.error-text {
  color: red;
  font-size: 0.8em;
  display: block;
}
.error-message {
  color: red;
  padding: 0.5rem;
  border: 1px solid red;
}
.success-message {
  color: green;
  padding: 0.5rem;
  border: 1px solid green;
}
</style>

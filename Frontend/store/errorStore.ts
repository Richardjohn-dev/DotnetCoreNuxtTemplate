// store/errorStore.ts
import { defineStore } from "pinia";
import type { ProblemDetails } from "~/types";

interface ErrorState {
  problemDetails: ProblemDetails | null;
  generalError: { title: string; detail?: string } | null;
}

export const useErrorStore = defineStore("error", {
  state: (): ErrorState => ({
    problemDetails: null,
    generalError: null,
  }),

  getters: {
    hasError: (state): boolean =>
      !!state.problemDetails || !!state.generalError,
    errorTitle: (state): string | undefined =>
      state.problemDetails?.title || state.generalError?.title,
    errorDetail: (state): string | undefined =>
      state.problemDetails?.detail || state.generalError?.detail,
    validationErrors: (state): Record<string, string[]> | undefined =>
      state.problemDetails?.errors,
    hasValidationErrors: (state): boolean =>
      !!state.problemDetails?.errors &&
      Object.keys(state.problemDetails.errors).length > 0,
  },

  actions: {
    setError(error: unknown) {
      this.clearErrors();

      if (error instanceof Error) {
        this.generalError = {
          title: error.name,
          detail: error.message,
        };
      } else if (error && typeof error === "object" && "type" in error) {
        // Looks like a ProblemDetails object
        this.problemDetails = error as ProblemDetails;
      } else {
        // Fallback for other error types
        this.generalError = {
          title: "Error",
          detail:
            typeof error === "string" ? error : "An unexpected error occurred",
        };
      }
    },

    clearErrors() {
      this.problemDetails = null;
      this.generalError = null;
    },
  },
});

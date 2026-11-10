package dockerengine

import "testing"

func TestReservedImageMetadataCannotReplaceExecutionOwnership(t *testing.T) {
	want := map[string]string{LabelPrefix + "template": "linux-github-kata-v2", LabelPrefix + "installation": "host-a", LabelPrefix + "execution": "execution-a"}
	image := map[string]string{LabelPrefix + "guest-storage-driver": "overlay2", LabelPrefix + "storage-backing": "guest-local-block-ext4-required", LabelPrefix + "qualification": "required"}
	actual := map[string]string{}
	for k, v := range want {
		actual[k] = v
	}
	for k, v := range image {
		actual[k] = v
	}
	if !labelsMatchImage(actual, want, image) {
		t.Fatal("shipped image metadata rejected")
	}
	if labelsMatch(actual, want) {
		t.Fatal("unverified reserved labels accepted")
	}
	actual[LabelPrefix+"execution"] = "execution-b"
	if labelsMatchImage(actual, want, image) {
		t.Fatal("image metadata replaced execution ownership")
	}
	actual[LabelPrefix+"execution"] = "execution-a"
	actual[LabelPrefix+"unknown-authority"] = "granted"
	if labelsMatchImage(actual, want, image) {
		t.Fatal("extra reserved authority accepted")
	}
	delete(actual, LabelPrefix+"unknown-authority")
	actual[LabelPrefix+"qualification"] = "qualified"
	if labelsMatchImage(actual, want, image) {
		t.Fatal("runtime metadata override accepted")
	}
	actual[LabelPrefix+"qualification"] = "required"
	want[LabelPrefix+"template"] = "linux-github-standard-v1"
	actual[LabelPrefix+"template"] = want[LabelPrefix+"template"]
	if labelsMatchImage(actual, want, image) {
		t.Fatal("block metadata exception applied to another profile")
	}
}
